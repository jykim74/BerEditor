#ifndef DNSLOOKUP_H
#define DNSLOOKUP_H

#include <QString>
#include <QStringList>
#include <QUdpSocket>

class DnsLookup
{
public:
    DnsLookup();

    bool lookup(const QString& dnsServer,
                int nPort,
                const QString& domain,
                QStringList& txtRecords,
                int timeout = 3000);

    QString lastError() const;

private:

    QByteArray createQuery(const QString& domain);

    QString readName(const QByteArray& data,
                     int& offset);

private:

    QUdpSocket socket_;
    quint16 id_;
    QString error_;
};

#endif
