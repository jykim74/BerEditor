#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "acme_object.h"
#include "common.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_eddsa.h"

ACMEObject::ACMEObject(QObject *parent)
    : QObject{parent}
{

}

void ACMEObject::setProtected( const QString strProtected )
{
    mProtected = strProtected;
}

void ACMEObject::setPayload( const QString strPayload )
{
    mPayload = strPayload;
}

void ACMEObject::setSignature( const QString strSignature )
{
    mSignature = strSignature;
}

void ACMEObject::setPayload( const QString strStatus,
                const QStringList listEmail,
                bool bTermsOfServiceAgreed,
                const QString strOrders )
{
    QJsonDocument jDoc;
    QJsonObject jObj;
    QJsonArray jArr;

    for( int i = 0; i < listEmail.size(); i++ )
    {
        QString strVal = QString( "mailto:%1").arg( listEmail.at(i));
        jArr.insert( i, strVal );
    }

    jObj["status"] = strStatus;
    jObj["contact"] = jArr;
    jObj["termsOfServiceAgreed"] = bTermsOfServiceAgreed;
    jObj["orders"] = strOrders;

    jDoc.setObject( jObj );
    mPayload = jDoc.toJson();
}

void ACMEObject::setProtected( const QString strAlg,
                  const QString strKid,
                  const QString strNonce,
                  const QString strURL )
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    jObj["alg"] = strAlg;
    jObj["kid"] = strKid;
    jObj["nonce"] = strNonce;
    jObj["url"] = strURL;

    jDoc.setObject( jObj );
    mProtected = jDoc.toJson();
}

const QString ACMEObject::getJson()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    jObj["protected"] = mProtected;
    jObj["payload"] = mPayload;
    jObj["signature"] = mSignature;

    jDoc.setObject( jObj );

    return jDoc.toJson();
}

const QString ACMEObject::getJWK( const BIN *pPub )
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    int nKeyType = JS_PKI_getPubKeyType( pPub );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAVal;

        memset( &sRSAVal, 0x00, sizeof(JRSAKeyVal) );

        JS_PKI_getRSAKeyValFromPub( pPub, &sRSAVal );
        jObj["kty"] = "RSA";
        jObj["alg"] = "RS256";
        jObj["n"] = getBase64URL_FromHex( sRSAVal.pN );
        jObj["e"] = getBase64URL_FromHex( sRSAVal.pE );
        jObj["kid"] = "2011-11-23";

        JS_PKI_resetRSAKeyVal( &sRSAVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        JECKeyVal sECVal;
        memset( &sECVal, 0x00, sizeof(JECKeyVal));
        JS_PKI_getECKeyValFromPub( pPub, &sECVal );

        jObj["crv"] = "P-256";
        jObj["kty"] = "EC";
        jObj["x"] = getBase64URL_FromHex( sECVal.pPubX );
        jObj["y"] = getBase64URL_FromHex( sECVal.pPubY );
        jObj["kid"] = "Public key used in JWS spec Appendix A.3 example";

        JS_PKI_resetECKeyVal( &sECVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        JDSAKeyVal sDSAVal;
        memset( &sDSAVal, 0x00, sizeof(JDSAKeyVal));
        JS_PKI_getDSAKeyValFromPub( pPub, &sDSAVal );

        jObj["kty"] = "DSA";
        jObj["p"] = getBase64URL_FromHex( sDSAVal.pP );
        jObj["q"] = getBase64URL_FromHex( sDSAVal.pQ );
        jObj["g"] = getBase64URL_FromHex( sDSAVal.pG );
        jObj["y"] = getBase64URL_FromHex( sDSAVal.pPublic );

        JS_PKI_resetDSAKeyVal( &sDSAVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ED25519 || nKeyType == JS_PKI_KEY_TYPE_ED448 )
    {
        JRawKeyVal sRawVal;
        memset( &sRawVal, 0x00, sizeof(JRawKeyVal));
        JS_PKI_getRawKeyValFromPub( nKeyType, pPub, &sRawVal );

        jObj["kty"] = "OKP";
        jObj["crv"] = "Ed25519";
        jObj["x"] = getBase64URL_FromHex( sRawVal.pPub );

        JS_PKI_resetRawKeyVal( &sRawVal );
    }

    jDoc.setObject( jObj );
    return jDoc.toJson();
}
