#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "acme_object.h"
#include "common.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"

ACMEObject::ACMEObject(QObject *parent)
    : QObject{parent}
{

}

void ACMEObject::setProtected( const QJsonObject object )
{
    json_[kNameProtected] = object;
}

void ACMEObject::setPayload( const QJsonObject objPayload )
{
    json_[kNamePayload] = objPayload;
}

const QString ACMEObject::getProtectedJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    jObj = json_[kNameProtected].toObject();
    jDoc.setObject( jObj );

    return jDoc.toJson();
}

const QString ACMEObject::getPayloadJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    jObj = json_[kNamePayload].toObject();
    jDoc.setObject( jObj );

    return jDoc.toJson();
}

const QString ACMEObject::getSignatureJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    jObj = json_[kNameSignature].toObject();
    jDoc.setObject( jObj );

    return jDoc.toJson();
}

const QString ACMEObject::getPayloadPacket()
{
    BIN binData = {0,0};
    char *pValue = NULL;
    QString strPacket;

    QString strJson = getPayloadJSON();

    JS_BIN_set( &binData, (unsigned char *)strJson.toStdString().c_str(), strJson.length() );
    JS_BIN_encodeBase64URL( &binData, &pValue );

    if( pValue )
    {
        strPacket = pValue;
        JS_free( pValue );
    }

    return strPacket;
}

const QString ACMEObject::getProtectedPacket()
{
    BIN binData = {0,0};
    char *pValue = NULL;
    QString strPacket;

    QString strJson = getProtectedJSON();

    JS_BIN_set( &binData, (unsigned char *)strJson.toStdString().c_str(), strJson.length() );
    JS_BIN_encodeBase64URL( &binData, &pValue );

    if( pValue )
    {
        strPacket = pValue;
        JS_free( pValue );
    }

    return strPacket;
}

void ACMEObject::setSignature( const BIN *pPri,const QString strHash )
{
    int nKeyType = -1;
    BIN binSrc = {0,0};
    BIN binSign = {0,0};
    void *pCTX = NULL;
    char *pHexVal = NULL;

    QJsonObject objPayload = json_[kNamePayload].toObject();
    QJsonObject objProtected = json_[kNameProtected].toObject();

    QString strPayload;
    QString strProtected;

    QString strJSON;

    if( pPri == NULL ) return;

    nKeyType = JS_PKI_getPriKeyType( pPri );
    if( nKeyType < 0 ) return;


    strPayload = getPayloadPacket();
    strProtected = getProtectedPacket();

    strJSON = strProtected;
    strJSON += ".";
    strJSON += strPayload;

    JS_BIN_set( &binSrc, (unsigned char *)strJSON.toStdString().c_str(), strJSON.length() );

#if 0
    if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        BIN binR = {0,0};
        BIN binS = {0,0};
        JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, pPri, &binSign );

        JS_PKI_decodeECCSign( &binSign, &binR, &binS );
        JS_BIN_reset( &binSign );
        JS_BIN_copy( &binSign, &binR );
        JS_BIN_appendBin( &binSign, &binS );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
    }
    else
    {
        JS_PKI_signInit( &pCTX, strHash.toStdString().c_str(), nKeyType, pPri );
        JS_PKI_sign( pCTX, &binSrc, &binSign );
    }
#else
    JS_PKI_signInit( &pCTX, strHash.toStdString().c_str(), nKeyType, pPri );
    JS_PKI_sign( pCTX, &binSrc, &binSign );

    if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        BIN binR = {0,0};
        BIN binS = {0,0};

        JS_PKI_decodeECCSign( &binSign, &binR, &binS );
        JS_BIN_reset( &binSign );
        JS_BIN_copy( &binSign, &binR );
        JS_BIN_appendBin( &binSign, &binS );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
    }
#endif

    JS_BIN_encodeBase64URL( &binSign, &pHexVal );
    json_[kNameSignature] = pHexVal;

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binSign );
    if( pHexVal ) JS_free( pHexVal );
    if( pCTX ) JS_PKI_signFree( &pCTX );
}

const QJsonObject ACMEObject::getNewAccountPayload( const QString strStatus,
                const QStringList listEmail,
                bool bTermsOfServiceAgreed,
                const QString strOrders )
{
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

    if( strOrders.length() > 0 )
        jObj["orders"] = strOrders;

    return jObj;
}

const QJsonObject ACMEObject::getIdentifiers( const QStringList strNameList )
{
    QJsonObject jObj;
    QJsonArray jArr;
    QJsonObject jSubObj;

    for( int i = 0; i < strNameList.size(); i++ )
    {
        QString strName = strNameList.at(i);

        jSubObj["type"] = "dns";
        jSubObj["value"] = strName;

        jArr.append( jSubObj );
    }

    jObj["identifiers"] = jArr;

    return jObj;
}

const QJsonObject ACMEObject::getJWKProtected( const QString strAlg,
                                 const QJsonObject objJWK,
                                 const QString strNonce,
                                 const QString strURL )
{
    QJsonObject object;

    object["alg"] = strAlg;
    object["jwk"] = objJWK;
    object["nonce"] = strNonce;
    object["url"] = strURL;

    return object;
}

const QJsonObject ACMEObject::getKidProtected( const QString strAlg,
                  const QString strKid,
                  const QString strNonce,
                  const QString strURL )
{
    QJsonObject object;

    object["alg"] = strAlg;
    object["kid"] = strKid;
    object["nonce"] = strNonce;
    object["url"] = strURL;

    return object;
}

const QString ACMEObject::getJson()
{
    QJsonDocument jDoc;

    jDoc.setObject( json_ );

    return jDoc.toJson();
}

const QString ACMEObject::getPacketJson()
{
    QJsonDocument jDoc;
    QJsonObject objPayload;
    QJsonObject objProtected;

    QString strPayload;
    QString strProtected;

    BIN binPayload = {0,0};
    BIN binProtected = {0,0};

    char *pPayload = NULL;
    char *pProtected = NULL;

    objProtected = json_[kNameProtected].toObject();
    objPayload = json_[kNamePayload].toObject();

    jDoc.setObject( objPayload );
    strPayload = jDoc.toJson();

    jDoc.setObject( objProtected );
    strProtected = jDoc.toJson();

    JS_BIN_set( &binPayload, (unsigned char *)strPayload.toStdString().c_str(), strPayload.length() );
    JS_BIN_set( &binProtected, (unsigned char *)strProtected.toStdString().c_str(), strProtected.length() );

    JS_BIN_encodeBase64URL( &binPayload, &pPayload );
    JS_BIN_encodeBase64URL( &binProtected, &pProtected );

    json_[kNameProtected] = pProtected;
    json_[kNamePayload] = pPayload;

    jDoc.setObject( json_ );

end :
    JS_BIN_reset( &binPayload );
    JS_BIN_reset( &binProtected );
    if( pPayload ) JS_free( pPayload );
    if( pProtected ) JS_free( pProtected );

    return jDoc.toJson();
}

const QJsonObject ACMEObject::getJWK( const BIN *pPub, const QString strHash, const QString strName )
{
    QJsonObject jObj;

    int nKeyType = JS_PKI_getPubKeyType( pPub );
    QString strAlg = getAlg( nKeyType, strHash );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAVal;

        memset( &sRSAVal, 0x00, sizeof(JRSAKeyVal) );

        JS_PKI_getRSAKeyValFromPub( pPub, &sRSAVal );
        jObj["kty"] = "RSA";
        if( strAlg.length() > 0 ) jObj["alg"] = strAlg;
        jObj["n"] = getBase64URL_FromHex( sRSAVal.pN );
        jObj["e"] = getBase64URL_FromHex( sRSAVal.pE );
        jObj["kid"] = strName;

        JS_PKI_resetRSAKeyVal( &sRSAVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        JECKeyVal sECVal;
        memset( &sECVal, 0x00, sizeof(JECKeyVal));
        JS_PKI_getECKeyValFromPub( pPub, &sECVal );

        jObj["crv"] = getCurve( sECVal.pCurveOID );
        jObj["kty"] = "EC";
    //    if( strAlg.length() > 0 ) jObj["alg"] = strAlg;
        jObj["x"] = getBase64URL_FromHex( sECVal.pPubX );
        jObj["y"] = getBase64URL_FromHex( sECVal.pPubY );
        jObj["kid"] = strName;

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
        jObj["crv"] = getEdDSA( sRawVal.pName );
        jObj["x"] = getBase64URL_FromHex( sRawVal.pPub );

        JS_PKI_resetRawKeyVal( &sRawVal );
    }

    return jObj;
}


const QString ACMEObject::getAlg( int nKeyType, const QString strHash )
{
    QString strAlg;

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        if( strHash.toUpper() == "SHA1" )
            strAlg = "RS1";
        else if( strHash.toUpper() == "SHA224" )
            strAlg = "RS224";
        else if( strHash.toUpper() == "SHA256" )
            strAlg = "RS256";
        else if( strHash.toUpper() == "SHA384" )
            strAlg = "RS384";
        else if( strHash.toUpper() == "SHA512" )
            strAlg = "RS512";
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        if( strHash.toUpper() == "SHA1" )
            strAlg = "ES1";
        else if( strHash.toUpper() == "SHA224" )
            strAlg = "ES224";
        else if( strHash.toUpper() == "SHA256" )
            strAlg = "ES256";
        else if( strHash.toUpper() == "SHA384" )
            strAlg = "ES384";
        else if( strHash.toUpper() == "SHA512" )
            strAlg = "ES512";
    }

    return strAlg;
}

const QString ACMEObject::getCurve( const QString strOID )
{
    QString strCurve;

    if( strOID == "1.2.840.10045.3.1.7" ) // prime256v1
        strCurve = "P-256";
    else if( strOID == "1.3.132.0.34" ) // secp384r1
        strCurve = "P-384";
    else if( strOID == "1.3.132.0.35" ) // secp521r1"
        strCurve = "P-521";

    return strCurve;
}

const QString ACMEObject::getEdDSA( const QString strName )
{
    QString strEdDSA;

    if( strName.toUpper() == "ED25519" )
        strEdDSA = "Ed25519";
    else if( strName.toUpper() == "ED448" )
        strEdDSA = "Ed448";

    return strEdDSA;
}
