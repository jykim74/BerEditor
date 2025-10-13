#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "acme_object.h"
#include "common.h"
#include "ber_applet.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_raw.h"
#include "js_pki_tools.h"
#include "js_bin.h"
#include "js_error.h"

ACMEObject::ACMEObject(QObject *parent)
    : QObject{parent}
{

}

void ACMEObject::setObject( const QJsonObject object )
{
    json_ = object;
}

void ACMEObject::setObjectFromJson( const QString strJson )
{
    BIN binProtected = {0,0};
    BIN binPayload = {0,0};
    char *pProtected = NULL;
    char *pPayload = NULL;

    QJsonDocument jDoc = QJsonDocument::fromJson( strJson.toLocal8Bit() );
    QJsonObject jObj = jDoc.object();

    QString strProtected = jObj[kNameProtected].toString();
    QString strPayload = jObj[kNamePayload].toString();
    QString strSignature = jObj[kNameSignature].toString();

    JS_BIN_decodeBase64URL( strProtected.toStdString().c_str(), &binProtected );
    JS_BIN_decodeBase64URL( strPayload.toStdString().c_str(), &binPayload );

    JS_BIN_string( &binProtected, &pProtected );
    JS_BIN_string( &binPayload, &pPayload );

    setProtected( QJsonDocument::fromJson( pProtected ).object() );
    setPayload( QJsonDocument::fromJson( pPayload ).object() );

//    json_[kNameProtected] = QJsonDocument::fromJson( pProtected ).object();
//    json_[kNamePayload] = QJsonDocument::fromJson( pPayload ).object();
    json_[kNameSignature] = strSignature;

    JS_BIN_reset( &binProtected );
    JS_BIN_reset( &binPayload );
    if( pProtected ) JS_free( pProtected );
    if( pPayload ) JS_free( pPayload );

    berApplet->log( QString( "JWS: %1" ).arg( getPacketJson() ));
}


void ACMEObject::setProtected( const QJsonObject object )
{
    json_[kNameProtected] = object;
}

void ACMEObject::setPayload( const QJsonObject objPayload )
{
    json_[kNamePayload] = objPayload;
}

void ACMEObject::setProtected( const QString strProtected )
{
    json_[kNameProtected] = strProtected;
}

void ACMEObject::setPayload( const QString strPayload )
{
    json_[kNamePayload] = strPayload;
}

const QString ACMEObject::getProtectedJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    if( json_[kNameProtected].isObject() == true )
    {
        jObj = json_[kNameProtected].toObject();
        jDoc.setObject( jObj );
        return jDoc.toJson();
    }
    else
    {
        return json_[kNameProtected].toString();
    }
}

const QString ACMEObject::getPayloadJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    if( json_[kNamePayload].isObject() == true )
    {
        jObj = json_[kNamePayload].toObject();
        jDoc.setObject( jObj );
        return jDoc.toJson();
    }
    else
    {
        return json_[kNamePayload].toString();
    }
}

const QString ACMEObject::getSignatureJSON()
{
    QJsonDocument jDoc;
    QJsonObject jObj;

    if( json_[kNameSignature].isObject() == true )
    {
        jObj = json_[kNameSignature].toObject();
        jDoc.setObject( jObj );
        return jDoc.toJson();
    }
    else
    {
        return json_[kNameSignature].toString();
    }
}

const QJsonObject ACMEObject::getProtected()
{
    return json_[kNameProtected].toObject();
}

const QJsonObject ACMEObject::getPayload()
{
    return json_[kNamePayload].toObject();
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

    JS_BIN_reset( &binData );
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

    JS_BIN_reset( &binData );
    return strPacket;
}

int ACMEObject::setSignature( const BIN *pPri,const QString strHash )
{
    int ret = -1;
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

    if( pPri == NULL ) return JSR_ERR;

    nKeyType = JS_PKI_getPriKeyType( pPri );
    if( nKeyType < 0 ) return JSR_INVALID_ALG;

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_EDDSA )
        return JSR_INVALID_ALG;

    strPayload = getPayloadPacket();
    strProtected = getProtectedPacket();

    strJSON = strProtected;

    strJSON += ".";
    strJSON += strPayload;


    JS_BIN_set( &binSrc, (unsigned char *)strJSON.toStdString().c_str(), strJSON.length() );
    ret = JS_PKI_signInit( &pCTX, strHash.toStdString().c_str(), nKeyType, pPri );
    if( ret != JSR_OK ) goto end;

    ret = JS_PKI_sign( pCTX, &binSrc, &binSign );
    if( ret != JSR_OK ) goto end;

    if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
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

    if( ret == JSR_OK )
    {
        berApplet->log( QString( "== Compute Signature =="));
        berApplet->log( QString( "JWS Hash      : %1").arg( strHash ));
        berApplet->log( QString( "JWS Source    : %1").arg( getHexString( &binSrc )));
        berApplet->log( QString( "JWS Signature : %1").arg( getHexString( &binSign )));

        JS_BIN_encodeBase64URL( &binSign, &pHexVal );
        json_[kNameSignature] = pHexVal;
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binSign );
    if( pHexVal ) JS_free( pHexVal );
    if( pCTX ) JS_PKI_signFree( &pCTX );
    return ret;
}

int ACMEObject::verifySignature( const BIN *pPub )
{
    int ret = 0;
    int nKeyType = -1;
    BIN binSrc = {0,0};
    BIN binSign = {0,0};
    void *pCTX = NULL;

    QJsonObject objPayload = json_[kNamePayload].toObject();
    QJsonObject objProtected = json_[kNameProtected].toObject();

    QString strPayload;
    QString strProtected;
    QString strSignature = json_[kNameSignature].toString();

    QString strJSON;
    QString strAlg = objProtected["alg"].toString();
    QString strHash = getHash( strAlg );

    if( pPub == NULL ) return -1;

    nKeyType = JS_PKI_getPubKeyType( pPub );
    if( nKeyType < 0 ) return -1;

    strPayload = getPayloadPacket();
    strProtected = getProtectedPacket();

    strJSON = strProtected;

    strJSON += ".";
    strJSON += strPayload;


    JS_BIN_set( &binSrc, (unsigned char *)strJSON.toStdString().c_str(), strJSON.length() );
    JS_BIN_decodeBase64URL( strSignature.toStdString().c_str(), &binSign );

    berApplet->log( QString( "== Verify Signature =="));
    berApplet->log( QString( "JWS Hash      : %1").arg( strHash ));
    berApplet->log( QString( "JWS Source    : %1").arg( getHexString( &binSrc )));
    berApplet->log( QString( "JWS Signature : %1").arg( getHexString( &binSign )));

    if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
    {
        BIN binR = {0,0};
        BIN binS = {0,0};

        JS_BIN_set( &binR, binSign.pVal, binSign.nLen / 2 );
        JS_BIN_set( &binS, &binSign.pVal[binR.nLen], binR.nLen );
        JS_BIN_reset( &binSign );
        JS_PKI_encodeECCSign( &binR, &binS, &binSign );
        JS_BIN_reset( &binR );
        JS_BIN_reset( &binS );
    }

    ret = JS_PKI_verifyInit( &pCTX, strHash.toStdString().c_str(), nKeyType, pPub );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    ret = JS_PKI_verify( pCTX, &binSrc, &binSign );

end :
    JS_BIN_reset( &binSrc );
    if( pCTX ) JS_PKI_verifyFree( &pCTX );

    return ret;
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
    if(strNonce.length() > 0 ) object["nonce"] = strNonce;
    if( strURL.length() > 0 ) object["url"] = strURL;

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
    QJsonObject jObj;

    jObj[kNameProtected] = getProtectedPacket();
    jObj[kNamePayload] = getPayloadPacket();
    jObj[kNameSignature] = json_[kNameSignature].toString();

    jDoc.setObject( jObj );

end :

    return jDoc.toJson();
}

const QString ACMEObject::getObjectPacket( const QJsonObject obj )
{
    BIN binData = {0,0};
    char *pValue = NULL;
    QString strPacket;

    QJsonDocument jDoc;
    jDoc.setObject( obj );
    QString strJson = jDoc.toJson();

    JS_BIN_set( &binData, (unsigned char *)strJson.toStdString().c_str(), strJson.length() );
    JS_BIN_encodeBase64URL( &binData, &pValue );

    if( pValue )
    {
        strPacket = pValue;
        JS_free( pValue );
    }

    JS_BIN_reset( &binData );
    return strPacket;
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
    else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
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
    else if( nKeyType == JS_PKI_KEY_TYPE_EDDSA )
    {
        JRawKeyVal sRawVal;
        memset( &sRawVal, 0x00, sizeof(JRawKeyVal));
        JS_PKI_getRawKeyValFromPub( pPub, &sRawVal );

        jObj["kty"] = "OKP";
        jObj["crv"] = getEdDSA( sRawVal.pParam );
        jObj["x"] = getBase64URL_FromHex( sRawVal.pPub );

        JS_PKI_resetRawKeyVal( &sRawVal );
    }

    return jObj;
}

int ACMEObject::getPubKey( QJsonObject objKey, BIN *pPub )
{
    QString strKTY = objKey["kty"].toString();

    if( strKTY == "RSA" )
    {
        JRSAKeyVal sRSAVal;
        QString strN = getHex_FromBase64URL( objKey["n"].toString() );
        QString strE = getHex_FromBase64URL( objKey["e"].toString() );

        memset( &sRSAVal, 0x00, sizeof(sRSAVal));

        JS_PKI_setRSAKeyVal( &sRSAVal,
                            strN.toStdString().c_str(),
                            strE.toStdString().c_str(),
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL );

        JS_PKI_encodeRSAPublicKey( &sRSAVal, pPub );
        JS_PKI_resetRSAKeyVal( &sRSAVal );
    }
    else if( strKTY == "EC" )
    {
        JECKeyVal sECVal;

        QString strOID = getCurveOID( objKey["crv"].toString() );
        QString strX = getHex_FromBase64URL( objKey["x"].toString() );
        QString strY = getHex_FromBase64URL( objKey["y"].toString() );

        memset( &sECVal, 0x00, sizeof(sECVal));

        JS_PKI_setECKeyVal( &sECVal,
                            strOID.toStdString().c_str(),
                            strX.toStdString().c_str(),
                            strY.toStdString().c_str(),
                            NULL );

        JS_PKI_encodeECPublicKey( &sECVal, pPub );
        JS_PKI_resetECKeyVal( &sECVal );
    }
    else if( strKTY == "DSA" )
    {
        JDSAKeyVal sDSAVal;
        QString strP = getHex_FromBase64URL( objKey["p"].toString() );
        QString strQ = getHex_FromBase64URL( objKey["q"].toString() );
        QString strG = getHex_FromBase64URL( objKey["g"].toString() );
        QString strY = getHex_FromBase64URL( objKey["y"].toString() );

        memset( &sDSAVal, 0x00, sizeof(sDSAVal));

        JS_PKI_setDSAKeyVal( &sDSAVal,
                            strQ.toStdString().c_str(),
                            strP.toStdString().c_str(),
                            strQ.toStdString().c_str(),
                            strY.toStdString().c_str(),
                            NULL );

        JS_PKI_encodeDSAPrivateKey( &sDSAVal, pPub );
        JS_PKI_resetDSAKeyVal( &sDSAVal );
    }
    else if( strKTY == "OKP" )
    {
        JRawKeyVal sRawVal;
        QString strCrv = objKey["crv"].toString();
        QString strX = getHex_FromBase64URL( objKey["x"].toString() );

        memset( &sRawVal, 0x00, sizeof(sRawVal));

        JS_PKI_setRawKeyVal( &sRawVal,
                            "EDDSA",
                            strCrv.toUpper().toStdString().c_str(),
                            strX.toStdString().c_str(),
                            NULL );

        JS_PKI_encodeRawPublicKey( &sRawVal, pPub );
        JS_PKI_resetRawKeyVal( &sRawVal );
    }
    else
    {
        return JSR_ERR;
    }

    return 0;
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
    else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
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

const QString ACMEObject::getHash( const QString strAlg )
{
    QString strHash;

    if( strAlg == "RS1" || strAlg == "ES1" )
        strHash = "SHA1";
    else if( strAlg == "RS224" || strAlg == "ES224" )
        strHash = "SHA224";
    else if( strAlg == "RS256" || strAlg == "ES256" )
        strHash = "SHA256";
    else if( strAlg == "RS384" || strAlg == "ES384" )
        strHash = "SHA384";
    else if( strAlg == "RS512" || strAlg == "ES512" )
        strHash = "SHA512";

    return strHash;
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

const QString ACMEObject::getCurveOID( const QString strCurve )
{
    QString strOID;

    if( strCurve == "P-256" ) // prime256v1
        strOID = "1.2.840.10045.3.1.7";
    else if( strCurve == "P-384" ) // secp384r1
        strOID = "1.3.132.0.34";
    else if( strOID == "P-521" ) // secp521r1"
        strOID = "1.3.132.0.35";

    return strOID;
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
