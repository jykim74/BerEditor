#ifndef DNS_CHECK_DLG_H
#define DNS_CHECK_DLG_H

#include <QDialog>
#include <QCoreApplication>
#include <QUdpSocket>
#include <QDataStream>
#include <QDebug>

#include "ui_dns_check_dlg.h"
#include "js_bin.h"

namespace Ui {
class DNSCheckDlg;
}

enum ACME_CheckType {
    ACME_HTTP_01 = 0,
    ACME_DNS_01,
    ACME_TLS_ALPN_01
};

class DnsQuery
{
public:
    static QByteArray buildQuery(const QString &domain)
    {
        QByteArray packet;
        QDataStream out(&packet, QIODevice::WriteOnly);
        out.setByteOrder(QDataStream::BigEndian);

        // DNS Header
        out << (quint16)0x1234;      // Transaction ID
        out << (quint16)0x0100;      // Standard Query
        out << (quint16)1;           // Questions
        out << (quint16)0;           // Answer RRs
        out << (quint16)0;           // Authority RRs
        out << (quint16)0;           // Additional RRs

        // QNAME
        QStringList labels = domain.split('.');
        for (const QString &label : labels)
        {
            out << (quint8)label.size();
            packet.append(label.toUtf8());
        }
        out << (quint8)0;

        // QTYPE = TXT (16)
        out << (quint16)16;

        // QCLASS = IN
        out << (quint16)1;

        return packet;
    }

    static void parseResponse(const QByteArray &data)
    {
        if (data.size() < 12)
            return;

        const uchar *p = (const uchar*)data.constData();

        quint16 answerCount = (p[6] << 8) | p[7];

        int pos = 12;

        // Skip Question
        while (p[pos] != 0)
            pos += p[pos] + 1;
        pos += 5;

        for (int i = 0; i < answerCount; i++)
        {
            pos += 2; // Name(pointer)

            quint16 type = (p[pos] << 8) | p[pos+1];
            pos += 2;

            pos += 2; // Class
            pos += 4; // TTL

            quint16 rdlen = (p[pos] << 8) | p[pos+1];
            pos += 2;

            if (type == 16) // TXT
            {
                int end = pos + rdlen;

                while (pos < end)
                {
                    quint8 len = p[pos++];
                    QByteArray txt((const char*)&p[pos], len);
                    qDebug() << "TXT =" << txt;
                    pos += len;
                }
            }
            else
            {
                pos += rdlen;
            }
        }
    }
};

class DNSCheckDlg : public QDialog, public Ui::DNSCheckDlg
{
    Q_OBJECT

public:
    explicit DNSCheckDlg(QWidget *parent = nullptr);
    ~DNSCheckDlg();

    void addDNS( const QString strDNS );
    void setPubKey( const BIN *pPubKey );
    void setToken( const QString strToken );

private slots:
    void clickHTTP01();
    void clickDNS01();
    void clickTLS_ALPN01();
    void clickMakeSelfSignCert();

private:
    void initUI();
    void initialize();

    QString getDefault();
    void setDefault( const QString strDefault );

    int checkHTTP01( const QString strDNS, const QString strToken, const BIN *pPub );
    int checkDNS01( const QString strDNS, const QString strToken, const BIN *pPub );
    int checkTLS_ALPN01( const QString strDNS, const QString strToken, const BIN *pPub );
    void checkDNS( ACME_CheckType type );
    int savePriKeyCert( const BIN *pPriKey, const BIN *pCert );

    BIN pub_key_;
};

#endif // DNS_CHECK_DLG_H
