#ifndef ACME_OBJECT_H
#define ACME_OBJECT_H

#include <QObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "js_bin.h"

const QString kNameProtected = "protected";
const QString kNamePayload = "payload";
const QString kNameSignature = "signature";

class ACMEObject : public QObject
{
    Q_OBJECT
public:
    explicit ACMEObject(QObject *parent = nullptr);

    void setProtected( const QJsonObject object );
    void setPayload( const QJsonObject objPayload );
    void setSignature( const BIN *pPri, const QString strHash );
    int verifySignature( const BIN *pPub );

    const QString getProtectedJSON();
    const QString getPayloadJSON();
    const QString getSignatureJSON();

    const QString getPayloadPacket();
    const QString getProtectedPacket();

    const QString getJson();
    const QString getPacketJson();
    const QJsonObject getObject() { return json_; };
    void setObjectFromJson( const QString strJson );


    static const QJsonObject getJWKProtected( const QString strAlg,
                         const QJsonObject objJWK,
                         const QString strNonce,
                         const QString strURL );

    static const QJsonObject getKidProtected( const QString strAlg,
                      const QString strKid,
                      const QString strNonce,
                      const QString strURL );



    static const QJsonObject getNewAccountPayload( const QString strStatus,
                                              const QStringList listEmail,
                                              bool bTermsOfServiceAgreed,
                                              const QString strOrders );

    static const QJsonObject getIdentifiers( const QStringList strNameList );

    static const QJsonObject getJWK( const BIN *pPub, const QString strHash, const QString strName );
    static const QString getAlg( int nKeyType, const QString strHash );
    static const QString getHash( const QString strAlg );
    static const QString getCurve( const QString strOID );
    static const QString getEdDSA( const QString strName );


private:
    QJsonObject json_;
};

#endif // ACME_OBJECT_H
