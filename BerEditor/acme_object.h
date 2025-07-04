#ifndef ACME_OBJECT_H
#define ACME_OBJECT_H

#include <QObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "js_bin.h"

class ACMEObject : public QObject
{
    Q_OBJECT
public:
    explicit ACMEObject(QObject *parent = nullptr);

    const QJsonObject getProtected() { return mProtected; };
    const QJsonObject getPayload() { return mPayload; };
    const QJsonObject getSignature() { return mSignature; };

    void setProtected( const QJsonObject strProtected );
    void setPayload( const QJsonObject strPayload );
    void setSignature( const QJsonObject strSignature );

    void setSignature( const QString strPayload, const BIN *pPri, const QString strHash );



    void setJWKProtected( const QString strAlg,
                         const QString strJWK,
                         const QString strNonce,
                         const QString strURL );

    void setJWKProtected( const QString strAlg,
                         const QJsonObject objJWK,
                         const QString strNonce,
                         const QString strURL );

    void setKidProtected( const QString strAlg,
                      const QString strKid,
                      const QString strNonce,
                      const QString strURL );

    const QString getJson();

    static const QString getNewAccountPayload( const QString strStatus,
                                              const QStringList listEmail,
                                              bool bTermsOfServiceAgreed,
                                              const QString strOrders );

    static const QString getJWK( const BIN *pPub, const QString strHash, const QString strName );
    static const QJsonObject getJWK2( const BIN *pPub, const QString strHash, const QString strName );
    static const QString getAlg( int nKeyType, const QString strHash );
    static const QString getCurve( const QString strOID );
    static const QString getEdDSA( const QString strName );


private:
    QJsonObject mProtected;
    QJsonObject mPayload;
    QJsonObject mSignature;
};

#endif // ACME_OBJECT_H
