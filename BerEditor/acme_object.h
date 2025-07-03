#ifndef ACME_OBJECT_H
#define ACME_OBJECT_H

#include <QObject>
#include "js_bin.h"

class ACMEObject : public QObject
{
    Q_OBJECT
public:
    explicit ACMEObject(QObject *parent = nullptr);

    const QString getProtected() { return mProtected; };
    const QString getPayload() { return mPayload; };
    const QString getSignature() { return mSignature; };

    void setProtected( const QString strProtected );
    void setPayload( const QString strPayload );
    void setSignature( const QString strSignature );

    void setPayload( const QString strStatus,
                    const QStringList listEmail,
                    bool bTermsOfServiceAgreed,
                    const QString strOrders );

    void setProtected( const QString strAlg,
                      const QString strKid,
                      const QString strNonce,
                      const QString strURL );

    const QString getJson();

    static const QString getJWK( const BIN *pPub );

private:
    QString mProtected;
    QString mPayload;
    QString mSignature;
};

#endif // ACME_OBJECT_H
