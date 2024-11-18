#include "passwd_dlg.h"
#include "p11api.h"
#include "common.h"

#include "js_pki_key.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"
#include "js_pki_eddsa.h"

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID, const QString strPIN )
{
    int ret = 0;

    QString strPass;
    JP11_CTX    *pCTX = (JP11_CTX *)pP11CTX;

    int nFlags = 0;
    BIN binPIN = {0,0};

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;


    if( strPIN == nullptr || strPIN.length() < 1 )
    {
        PasswdDlg pinDlg;
        ret = pinDlg.exec();
        if( ret == QDialog::Accepted )
            strPass = pinDlg.mPasswdText->text();
    }
    else
    {
        strPass = strPIN;
    }

    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 || uSlotCnt < nSlotID )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( pCTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    getBINFromString( &binPIN, DATA_STRING, strPass );

    ret = JS_PKCS11_Login( pCTX, nUserType, binPIN.pVal, binPIN.nLen );
    JS_BIN_reset( &binPIN );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    return pCTX->hSession;
}

int genKeyPairWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub )
{
    JP11_CTX   *pP11CTX = NULL;

    int rv;

    pP11CTX = pCTX;

    CK_ATTRIBUTE sPubTemplate[20];
    CK_ULONG uPubCount = 0;
    CK_ATTRIBUTE sPriTemplate[20];
    CK_ULONG uPriCount = 0;
    CK_MECHANISM sMech;
    CK_KEY_TYPE keyType;

    CK_OBJECT_HANDLE uPubObj = 0;
    CK_OBJECT_HANDLE uPriObj = 0;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;

    BIN binLabel = {0,0};
    JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.toUtf8().length() );


    BIN binPubExponent = {0,0};
    BIN binGroup = {0,0};
    CK_ULONG	uModBitLen = 0;

    BIN binVal = {0,0};
    BIN binHash = {0,0};

    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};

    BIN binKey = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    char sCurveOID[128];

    memset( &sMech, 0x00, sizeof(sMech) );
    memset( sCurveOID, 0x00, sizeof(sCurveOID));

    if( strAlg == kMechPKCS11_RSA )
    {
        sMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        keyType = CKK_RSA;
    }
    else if( strAlg == kMechPKCS11_EC )
    {
        sMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
        keyType = CKK_ECDSA;
    }
    else if( strAlg == kMechPKCS11_DSA )
    {
        sMech.mechanism = CKM_DSA_KEY_PAIR_GEN;
        keyType = CKK_DSA;
    }

    sPubTemplate[uPubCount].type = CKA_CLASS;
    sPubTemplate[uPubCount].pValue = &pubClass;
    sPubTemplate[uPubCount].ulValueLen = sizeof( pubClass );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[uPubCount].pValue = &keyType;
    sPubTemplate[uPubCount].ulValueLen = sizeof( keyType );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_LABEL;
    sPubTemplate[uPubCount].pValue = binLabel.pVal;
    sPubTemplate[uPubCount].ulValueLen = binLabel.nLen;
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_ID;
    sPubTemplate[uPubCount].pValue = binLabel.pVal;
    sPubTemplate[uPubCount].ulValueLen = binLabel.nLen;
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        QString strDecimal = "";
        strDecimal = QString( "%1" ).arg( nExponent );
        JS_PKI_decimalToBin( strDecimal.toStdString().c_str(), &binPubExponent );

        sPubTemplate[uPubCount].type = CKA_PUBLIC_EXPONENT;
        sPubTemplate[uPubCount].pValue = binPubExponent.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubExponent.nLen;
        uPubCount++;

        uModBitLen = strParam.toInt();

        sPubTemplate[uPubCount].type = CKA_MODULUS_BITS;
        sPubTemplate[uPubCount].pValue = &uModBitLen;
        sPubTemplate[uPubCount].ulValueLen = sizeof( uModBitLen );
        uPubCount++;
    }
    else if( keyType == CKK_ECDSA )
    {
        JS_PKI_getOIDFromSN( strParam.toStdString().c_str(), sCurveOID );
        JS_PKI_getOIDFromString( sCurveOID, &binGroup );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binGroup.pVal;
        sPubTemplate[uPubCount].ulValueLen = binGroup.nLen;
        uPubCount++;
    }
    else if( keyType == CKK_DSA )
    {
        uModBitLen = strParam.toInt();
        JS_PKI_DSA_GenParamValue( uModBitLen, &binP, &binQ, &binG );

        sPubTemplate[uPubCount].type = CKA_PRIME;
        sPubTemplate[uPubCount].pValue = binP.pVal;
        sPubTemplate[uPubCount].ulValueLen = binP.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_SUBPRIME;
        sPubTemplate[uPubCount].pValue = binQ.pVal;
        sPubTemplate[uPubCount].ulValueLen = binQ.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_BASE;
        sPubTemplate[uPubCount].pValue = binG.pVal;
        sPubTemplate[uPubCount].ulValueLen = binG.nLen;
        uPubCount++;
    }

    sPubTemplate[uPubCount].type = CKA_TOKEN;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_VERIFY;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        sPubTemplate[uPubCount].type = CKA_ENCRYPT;
        sPubTemplate[uPubCount].pValue = &bTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_WRAP;
        sPubTemplate[uPubCount].pValue = &bTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
        uPubCount++;
    }

    /* Pri template */
    sPriTemplate[uPriCount].type = CKA_CLASS;
    sPriTemplate[uPriCount].pValue = &priClass;
    sPriTemplate[uPriCount].ulValueLen = sizeof( priClass );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_KEY_TYPE;
    sPriTemplate[uPriCount].pValue = &keyType;
    sPriTemplate[uPriCount].ulValueLen = sizeof( keyType );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_LABEL;
    sPriTemplate[uPriCount].pValue = binLabel.pVal;
    sPriTemplate[uPriCount].ulValueLen = binLabel.nLen;
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_ID;
    sPriTemplate[uPriCount].pValue = binLabel.pVal;
    sPriTemplate[uPriCount].ulValueLen = binLabel.nLen;
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_TOKEN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_PRIVATE;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    if( keyType == CKK_RSA )
    {
        sPriTemplate[uPriCount].type = CKA_DECRYPT;
        sPriTemplate[uPriCount].pValue = &bTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
        uPriCount++;

        sPriTemplate[uPriCount].type = CKA_UNWRAP;
        sPriTemplate[uPriCount].pValue = &bTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
        uPriCount++;
    }

    sPriTemplate[uPriCount].type = CKA_SENSITIVE;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_SIGN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    rv = JS_PKCS11_GenerateKeyPair( pP11CTX, &sMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubObj, &uPriObj );
    if( rv != 0 ) goto end;

    if( keyType == CKK_RSA )
    {
        char *pN = NULL;
        char *pE = NULL;

        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_MODULUS, &binVal );
        if( rv != 0 ) goto end;

        JRSAKeyVal  rsaKey;
        memset( &rsaKey, 0x00, sizeof(rsaKey));

        JS_BIN_encodeHex( &binVal, &pN );
        JS_BIN_encodeHex( &binPubExponent, &pE );

        JS_PKI_setRSAKeyVal( &rsaKey, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );
        JS_PKI_encodeRSAPublicKey( &rsaKey, pPub );

        if( pN ) JS_free( pN );
        if( pE ) JS_free( pE );
        JS_PKI_resetRSAKeyVal( &rsaKey );
    }
    else if( keyType == CKK_ECDSA )
    {
        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        char *pPubX = NULL;
        char *pPubY = NULL;

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        JS_BIN_set( &binKey, binVal.pVal + 3, binVal.nLen - 3 ); // 04+Len(1byte)+04 건너팀
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2 );
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );


        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );

        JS_PKI_setECKeyVal( &ecKey, sCurveOID, pPubX, pPubY, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );
        JS_BIN_reset( &binKey );
        JS_PKI_resetECKeyVal( &ecKey );
    }
    else if( keyType == CKK_DSA )
    {
        char *pHexG = NULL;
        char *pHexP = NULL;
        char *pHexQ = NULL;
        char *pHexPub = NULL;

        JDSAKeyVal sDSAKey;
        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_VALUE, &binVal );
        if( rv != 0 ) goto end;

        JS_BIN_encodeHex( &binP, &pHexP );
        JS_BIN_encodeHex( &binQ, &pHexQ );
        JS_BIN_encodeHex( &binG, &pHexG );
        JS_BIN_encodeHex( &binVal, &pHexPub );

        JS_PKI_setDSAKeyVal( &sDSAKey, pHexG, pHexP, pHexQ, pHexPub, NULL );
        JS_PKI_encodeDSAPublicKey( &sDSAKey, pPub );

        if( pHexG ) JS_free( pHexG );
        if( pHexP ) JS_free( pHexP );
        if( pHexQ ) JS_free( pHexQ );
        if( pHexPub ) JS_free( pHexPub );

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }

    //    JS_PKI_genHash( "SHA1", pPub, &binHash );
    JS_PKI_getKeyIdentifier( pPub, &binHash );
    JS_BIN_copy( pPri, &binHash );

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPriObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPubObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binPubExponent );
    JS_BIN_reset( &binGroup );
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binHash );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );

    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    return rv;
}

int createRSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strModulus = pRsaKeyVal->pN;
    BIN binModulus = {0,0};

    if( !strModulus.isEmpty() )
    {
        JS_BIN_decodeHex( strModulus.toStdString().c_str(), &binModulus );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModulus.pVal;
        sTemplate[uCount].ulValueLen = binModulus.nLen;
        uCount++;
    }

    QString strExponent = pRsaKeyVal->pE;
    BIN binExponent = {0,0};

    if( !strExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent.toStdString().c_str(), &binExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binExponent.pVal;
        sTemplate[uCount].ulValueLen = binExponent.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};
    JS_BIN_copy( &binID, pID );

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_VERIFY;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_ENCRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_WRAP;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binModulus );
    JS_BIN_reset( &binExponent );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createRSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;


    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strModules = pRsaKeyVal->pN;
    BIN binModules = {0,0};

    if( !strModules.isEmpty() )
    {
        JS_BIN_decodeHex( strModules.toStdString().c_str(), &binModules );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModules.pVal;
        sTemplate[uCount].ulValueLen = binModules.nLen;
        uCount++;
    }

    QString strPublicExponent = pRsaKeyVal->pE;
    BIN binPublicExponent = {0,0};

    if( !strPublicExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPublicExponent.toStdString().c_str(), &binPublicExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binPublicExponent.pVal;
        sTemplate[uCount].ulValueLen = binPublicExponent.nLen;
        uCount++;
    }

    QString strPrivateExponent = pRsaKeyVal->pD;
    BIN binPrivateExponent = {0,0};

    if( !strPrivateExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPrivateExponent.toStdString().c_str(), &binPrivateExponent );
        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binPrivateExponent.pVal;
        sTemplate[uCount].ulValueLen = binPrivateExponent.nLen;
        uCount++;
    }

    QString strPrime1 = pRsaKeyVal->pP;
    BIN binPrime1 = {0,0};

    if( !strPrime1.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime1.toStdString().c_str(), &binPrime1 );
        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binPrime1.pVal;
        sTemplate[uCount].ulValueLen = binPrime1.nLen;
        uCount++;
    }

    QString strPrime2 = pRsaKeyVal->pQ;
    BIN binPrime2 = {0,0};

    if( !strPrime2.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime2.toStdString().c_str(), &binPrime2 );
        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binPrime2.pVal;
        sTemplate[uCount].ulValueLen = binPrime2.nLen;
        uCount++;
    }

    QString strExponent1 = pRsaKeyVal->pDMP1;
    BIN binExponent1 = {0,0};

    if( !strExponent1.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent1.toStdString().c_str(), &binExponent1 );
        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binExponent1.pVal;
        sTemplate[uCount].ulValueLen = binExponent1.nLen;
        uCount++;
    }

    QString strExponent2 = pRsaKeyVal->pDMQ1;
    BIN binExponent2 = {0,0};

    if( !strExponent2.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent2.toStdString().c_str(), &binExponent2 );
        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binExponent2.pVal;
        sTemplate[uCount].ulValueLen = binExponent2.nLen;
        uCount++;
    }

    QString strCoefficient = pRsaKeyVal->pIQMP;
    BIN binCoefficient = {0,0};

    if( !strCoefficient.isEmpty() )
    {
        JS_BIN_decodeHex( strCoefficient.toStdString().c_str(), &binCoefficient );
        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binCoefficient.pVal;
        sTemplate[uCount].ulValueLen = binCoefficient.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length());
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof( objClass );
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof( keyType );
    uCount++;

    sTemplate[uCount].type = CKA_LABEL;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_DECRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_UNWRAP;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SENSITIVE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binModules );
    JS_BIN_reset( &binPublicExponent );
    JS_BIN_reset( &binPrivateExponent );
    JS_BIN_reset( &binPrime1 );
    JS_BIN_reset( &binPrime2 );
    JS_BIN_reset( &binExponent1 );
    JS_BIN_reset( &binExponent2 );
    JS_BIN_reset( &binCoefficient );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA private key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createECPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pEcKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pEcKeyVal->pCurveOID;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strECPoints = pEcKeyVal->pPubX;
    strECPoints += pEcKeyVal->pPubY;
    BIN binECPoints = {0,0};

    if( !strECPoints.isEmpty() )
    {
        JS_BIN_decodeHex( strECPoints.toStdString().c_str(), &binECPoints );
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binECPoints.pVal;
        sTemplate[uCount].ulValueLen = binECPoints.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_VERIFY;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binECPoints );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC public key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createECPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pECKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pECKeyVal->pCurveOID;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strValue = pECKeyVal->pPrivate;
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof( objClass );
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof( keyType );
    uCount++;

    sTemplate[uCount].type = CKA_LABEL;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SENSITIVE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );


    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC private key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strP = pDSAKeyVal->pP;
    BIN binP = {0,0};

    if( !strP.isEmpty() )
    {
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        sTemplate[uCount].type = CKA_PRIME;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    QString strQ = pDSAKeyVal->pQ;
    BIN binQ = {0,0};

    if( !strQ.isEmpty() )
    {
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
        sTemplate[uCount].type = CKA_SUBPRIME;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    QString strG = pDSAKeyVal->pG;
    BIN binG = {0,0};

    if( !strG.isEmpty() )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        sTemplate[uCount].type = CKA_BASE;
        sTemplate[uCount].pValue = binG.pVal;
        sTemplate[uCount].ulValueLen = binG.nLen;
        uCount++;
    }

    QString strPublic = pDSAKeyVal->pPublic;
    BIN binPublic = {0,0};

    if( !strPublic.isEmpty() )
    {
        JS_BIN_decodeHex( strPublic.toStdString().c_str(), &binPublic );
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binPublic.pVal;
        sTemplate[uCount].ulValueLen = binPublic.nLen;
        uCount++;
    }


    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_VERIFY;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPublic );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create DSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strP = pDSAKeyVal->pP;
    BIN binP = {0,0};

    if( !strP.isEmpty() )
    {
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        sTemplate[uCount].type = CKA_PRIME;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    QString strQ = pDSAKeyVal->pQ;
    BIN binQ = {0,0};

    if( !strQ.isEmpty() )
    {
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
        sTemplate[uCount].type = CKA_SUBPRIME;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    QString strG = pDSAKeyVal->pG;
    BIN binG = {0,0};

    if( !strG.isEmpty() )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        sTemplate[uCount].type = CKA_BASE;
        sTemplate[uCount].pValue = binG.pVal;
        sTemplate[uCount].ulValueLen = binG.nLen;
        uCount++;
    }

    QString strValue = pDSAKeyVal->pPrivate;
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof( objClass );
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof( keyType );
    uCount++;

    sTemplate[uCount].type = CKA_LABEL;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = binLabel.pVal;
    sTemplate[uCount].ulValueLen = binLabel.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SENSITIVE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf(stderr, "fail to create DSA private key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}
