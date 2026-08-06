#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>

class DnsLookup : public QObject
{
    Q_OBJECT

public:
    explicit DnsLookup(QObject *parent=nullptr);

    void lookup(const QString& dnsServer, int port,
                const QString& domain);

signals:

    void finished(QStringList txtRecords);
    void error(QString msg);

private slots:

    void readyRead();

private:

    QByteArray createQuery(const QString& domain);

    QString readName(const QByteArray& data,int& offset);

    QUdpSocket udp_;

    quint16 id_;
};


#endif // DNS_LOOKUP_H
