#include "xray.h"
#include "core/utils/networkUtilities.h"
#ifdef Q_OS_MAC
#include "router_mac.h"
#endif

#include <QDebug>
#include <QNetworkInterface>
#include <QCoreApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <amnezia_xray.h>
#include <qdebug.h>

#ifdef Q_OS_DARWIN
    #include <arpa/inet.h>
    #include <cerrno>
    #include <cstddef>
    #include <cstdint>
    #include <cstring>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <sys/socket.h>
#endif
#ifdef Q_OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif
#ifdef Q_OS_LINUX
    #include <sys/socket.h>
    #include "xray_defs.h"
#endif

#ifdef Q_OS_WIN
// Returns the outbound server address (IPv4 literal or hostname) from an xray config,
// or an empty string if it cannot be determined.
static QString xrayServerAddressFromConfig(const QString &cfg)
{
    const QJsonObject root = QJsonDocument::fromJson(cfg.toUtf8()).object();
    const QJsonArray outbounds = root.value("outbounds").toArray();
    for (const QJsonValue &ov : outbounds) {
        const QJsonObject settings = ov.toObject().value("settings").toObject();
        // vless / vmess
        const QJsonArray vnext = settings.value("vnext").toArray();
        if (!vnext.isEmpty()) {
            const QString a = vnext.first().toObject().value("address").toString();
            if (!a.isEmpty()) return a;
        }
        // shadowsocks / trojan
        const QJsonArray servers = settings.value("servers").toArray();
        if (!servers.isEmpty()) {
            const QString a = servers.first().toObject().value("address").toString();
            if (!a.isEmpty()) return a;
        }
        // vless/vmess "flat" form
        const QString flat = settings.value("address").toString();
        if (!flat.isEmpty()) return flat;
    }
    return {};
}
#endif

qint64 Xray::start(const QString &cfg)
{
    if (m_currentToken != 0) {
        qDebug() << "Xray::start() engine is busy (token" << m_currentToken << "), stopping it for the new owner";
        stopXray();
        m_currentToken = 0;
    }

    if (!startXray(cfg)) {
        return 0;
    }

    m_currentToken = ++m_lastToken;
    qDebug() << "Xray::start() engine started, owner token" << m_currentToken;
    return m_currentToken;
}

bool Xray::stop(qint64 token)
{
    if (m_currentToken == 0) {
        return true;
    }

    if (token == 0 || token != m_currentToken) {
        qDebug() << "Xray::stop() stale owner token" << token << "(current" << m_currentToken << "), ignoring";
        return true;
    }

    m_currentToken = 0;
    return stopXray();
}

bool Xray::stopAny()
{
    if (m_currentToken == 0) {
        return true;
    }

    m_currentToken = 0;
    return stopXray();
}

qint64 Xray::currentToken() const
{
    return m_currentToken;
}

bool Xray::startXray(const QString &cfg)
{
    qDebug() << "Xray::startXray()";
    const auto gatewayAndIface = NetworkUtilities::getGatewayAndIface();
    const QString defaultGateway = gatewayAndIface.first;
    const QNetworkInterface defaultIface = gatewayAndIface.second;
#ifdef Q_OS_LINUX
    m_defaultIfaceName = defaultIface.name().toUtf8();
#else
    m_defaultIfaceIdx = defaultIface.index();
#endif
#ifdef Q_OS_WIN
    // getGatewayAndIface() returns the *last* adapter that has a gateway, which is not
    // necessarily the one that routes to the xray server (e.g. server reachable only via
    // Tailscale, or a disabled/unused Wi-Fi adapter listed last). Ask the routing table instead.
    {
        const QString serverHost = xrayServerAddressFromConfig(cfg);
        QHostAddress serverAddr(serverHost);
        if (serverAddr.isNull() && !serverHost.isEmpty()) {
            serverAddr = QHostAddress(NetworkUtilities::getIPAddress(serverHost));
        }
        if (!serverAddr.isNull() && serverAddr.protocol() == QAbstractSocket::IPv4Protocol) {
            const int routedIdx = NetworkUtilities::AdapterIndexTo(serverAddr);
            if (routedIdx > 0) {
                qDebug() << "[xray] GetBestRoute to" << serverAddr.toString() << "-> ifIndex" << routedIdx
                         << "(was" << m_defaultIfaceIdx << ")";
                m_defaultIfaceIdx = routedIdx;
            } else {
                qWarning() << "[xray] GetBestRoute failed for" << serverAddr.toString()
                           << ", keeping ifIndex" << m_defaultIfaceIdx;
            }
        }
    }
#endif
    if (defaultIface.index() > 0) {
        qDebug() << "[xray] using uplink interface:" << defaultIface.name() << "(" << defaultIface.index() << ")";
    }

#ifdef Q_OS_MAC
    m_uplinkIfaceName = defaultIface.name();
    m_uplinkGateway = defaultGateway;
    if (!m_uplinkIfaceName.isEmpty()) {
        const bool installed = RouterMac::Instance().routeAddXray(m_uplinkIfaceName, m_uplinkGateway);
        if (!installed) {
            qWarning() << "[xray] failed to install xray routes on" << m_uplinkIfaceName;
        }
    }
#endif

    if (auto err = amnezia_xray_setsockcallback(ctxSockCallback, this); err != nullptr) {
        qDebug() << "[xray] sockopt failed: " << err;
        amnezia_xray_free(err);
        return false;
    }

    amnezia_xray_setloghandler(ctxLogHandler, this);

    QByteArray bytes = cfg.toUtf8();
    if (auto err = amnezia_xray_configure(bytes.data()); err != nullptr) {
        qDebug() << "[xray] configuration failed: " << err;
        amnezia_xray_free(err);
        return false;
    }

    if (auto err = amnezia_xray_start(); err != nullptr) {
        qDebug() << "[xray] failed to start: " << err;
        amnezia_xray_free(err);
        return false;
    }

    return true;
}

bool Xray::stopXray()
{
    qDebug() << "Xray::stopXray()";
    bool success = true;
    if (auto err = amnezia_xray_stop(); err != nullptr) {
        qDebug() << "[xray] failed to stop: " << err;
        amnezia_xray_free(err);
        success = false;
    }

#ifdef Q_OS_MAC
    if (!m_uplinkIfaceName.isEmpty()) {
        RouterMac::Instance().routeDeleteXray(m_uplinkIfaceName, m_uplinkGateway);
    }
    m_uplinkIfaceName.clear();
    m_uplinkGateway.clear();
#endif

    return success;
}

void Xray::logHandler(char* str)
{
    QMetaObject::invokeMethod(qApp, [str = QString::fromUtf8(str)] {
        qDebug() << "[xray]" << str;
    }, Qt::QueuedConnection);
}

void Xray::sockCallback(uintptr_t fd)
{
#ifdef Q_OS_MAC
    if (m_defaultIfaceIdx > 0) {
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
        setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
    }
#endif
#ifdef Q_OS_WIN
    if (DWORD idx = m_defaultIfaceIdx; idx > 0) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<char *>(&idx), sizeof(idx));
        idx = htonl(idx); // IP_UNICAST_IF expects index in network byte order
        setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<char *>(&idx), sizeof(idx));
    }
#endif
#ifdef Q_OS_LINUX
    if (!m_defaultIfaceName.isEmpty()) {
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, m_defaultIfaceName.data(), m_defaultIfaceName.size());
        setsockopt(fd, SOL_SOCKET, SO_MARK, &amnezia::xray::xrayTrafficMark, sizeof(amnezia::xray::xrayTrafficMark));
    }
#endif
}
