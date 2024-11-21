#include "passwd_dlg.h"
#include "p11api.h"
#include "common.h"

#include "js_pki_key.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"
#include "js_pki_eddsa.h"

long getP11KeyType( const QString strAlg )
{
    if( strAlg == "AES" )
        return CKK_AES;
    else if( strAlg == "SEED" )
        return CKK_SEED;
    else if( strAlg == "ARIA" )
        return CKK_ARIA;
    else if( strAlg == "TDES" || strAlg == "3DES" )
        return CKK_DES3;
    else if( strAlg == "RSA" )
        return CKK_RSA;
    else if( strAlg == "EC" || strAlg == "ECDSA" )
        return CKK_EC;
    else if( strAlg == "EDDSA" )
        return CKK_EC_EDWARDS;
    else if( strAlg == "HMAC" )
        return CKK_GENERIC_SECRET;

    return -1;
}

int loadPKCS11Libray( const QString strLibPath, JP11_CTX **ppCTX )
{
    int rv = 0;
    JP11_CTX *pCTX = NULL;

    if( strLibPath.length() < 1) return -1;

    rv = JS_PKCS11_LoadLibrary( (JP11_CTX **)&pCTX, strLibPath.toStdString().c_str() );
    if( rv != CKR_OK )
    {
        return rv;
    }

    rv = JS_PKCS11_Initialize( (JP11_CTX *)pCTX, NULL );
    if( rv != CKR_OK )
    {
        if( pCTX ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&pCTX );
    }

    if( rv == CKR_OK )
    {
        *ppCTX = pCTX;
    }

    return rv;
}

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotIndex )
{
    int ret = 0;

    JP11_CTX    *pCTX = (JP11_CTX *)pP11CTX;

    int nFlags = 0;

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];


    int nUserType = 0;

    CK_SESSION_INFO sSessInfo;
    memset( &sSessInfo, 0x00, sizeof(sSessInfo));

    ret = JS_PKCS11_GetSessionInfo( pCTX, &sSessInfo );
    if( ret == CKR_OK )
    {
        // 이미 세션이 열린 상태
        return ret;
    }

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;


    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 || uSlotCnt < nSlotIndex )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( pCTX, sSlotList[nSlotIndex], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    return pCTX->hSession;
}


CK_SESSION_HANDLE getP11SessionLogin( void *pP11CTX, int nSlotIndex, const QString strPIN )
{
    int ret = 0;

    QString strPass;
    JP11_CTX    *pCTX = (JP11_CTX *)pP11CTX;

    int nFlags = 0;
    BIN binPIN = {0,0};

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;
    int nState = -1;

    CK_SESSION_INFO sSessInfo;
    memset( &sSessInfo, 0x00, sizeof(sSessInfo));

    ret = JS_PKCS11_GetSessionInfo( pCTX, &sSessInfo );

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    if( ret == CKR_OK )
    {
        nState = sSessInfo.state;

        if( nState == CKS_RO_USER_FUNCTIONS || nState == CKS_RW_USER_FUNCTIONS )
        {
            return pCTX->hSession;
        }
    }

    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 || uSlotCnt < nSlotIndex )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    JS_PKCS11_CloseSession( pCTX );

    ret = JS_PKCS11_OpenSession( pCTX, sSlotList[nSlotIndex], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    if( strPIN == nullptr || strPIN.length() < 1 )
    {
        PasswdDlg pinDlg;
        pinDlg.setPasswordLabel( QString( "PIN") );

        ret = pinDlg.exec();
        if( ret == QDialog::Accepted )
            strPass = pinDlg.mPasswdText->text();
    }
    else
    {
        strPass = strPIN;
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

int genKeyWithP11( JP11_CTX *pCTX, QString strName, QString strAlg )
{
    int rv = -1;
    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = 0;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_OBJECT_HANDLE    hKey = 0;

    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));

    keyType = getP11KeyType( strAlg );

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( keyType >= 0 )
    {
        if( keyType == CKK_AES )
            sMech.mechanism = CKM_AES_KEY_GEN;
        else if( keyType == CKK_ARIA )
            sMech.mechanism = CKM_ARIA_KEY_GEN;
        else if( keyType == CKK_SEED )
            sMech.mechanism = CKM_SEED_KEY_GEN;
        else if( keyType == CKK_DES3 )
            sMech.mechanism = CKM_DES3_KEY_GEN;
        else
            sMech.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
    }
    else
    {
        sMech.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
    }

    BIN binLabel = {0,0};

    if( !strName.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    rv = JS_PKCS11_GenerateKey( pCTX, &sMech, sTemplate, uCount, &hKey );

    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
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

    keyType = getP11KeyType( strAlg );

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
        sMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

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
        sMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;

        JS_PKI_getOIDFromSN( strParam.toStdString().c_str(), sCurveOID );
        JS_PKI_getOIDFromString( sCurveOID, &binGroup );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binGroup.pVal;
        sPubTemplate[uPubCount].ulValueLen = binGroup.nLen;
        uPubCount++;
    }
    else if( keyType == CKK_EC_EDWARDS )
    {
        QString strCurveName = strParam;

        if( strCurveName == "ED25519" )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X25519;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X25519);
            uPubCount++;
        }
        else if( strCurveName == "ED448" )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X448;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X448);
            uPubCount++;
        }

        sMech.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
    }
    else if( keyType == CKK_DSA )
    {
        sMech.mechanism = CKM_DSA_KEY_PAIR_GEN;

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
    sPubTemplate[uPubCount].pValue = &kTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(kTrue);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_VERIFY;
    sPubTemplate[uPubCount].pValue = &kTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(kTrue);
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        sPubTemplate[uPubCount].type = CKA_ENCRYPT;
        sPubTemplate[uPubCount].pValue = &kTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(kTrue);
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_WRAP;
        sPubTemplate[uPubCount].pValue = &kTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(kTrue);
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
    sPriTemplate[uPriCount].pValue = &kTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_PRIVATE;
    sPriTemplate[uPriCount].pValue = &kTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
    uPriCount++;

    if( keyType == CKK_RSA )
    {
        sPriTemplate[uPriCount].type = CKA_DECRYPT;
        sPriTemplate[uPriCount].pValue = &kTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
        uPriCount++;

        sPriTemplate[uPriCount].type = CKA_UNWRAP;
        sPriTemplate[uPriCount].pValue = &kTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
        uPriCount++;
    }

    sPriTemplate[uPriCount].type = CKA_SENSITIVE;
    sPriTemplate[uPriCount].pValue = &kTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_SIGN;
    sPriTemplate[uPriCount].pValue = &kTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( kTrue );
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

int createKeyWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, const BIN *pSecret )
{
    int rv = -1;
    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = 0;
    CK_OBJECT_HANDLE    hObject = 0;

    keyType = getP11KeyType( strAlg );

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( keyType >= 0 )
    {
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strName.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};
    JS_PKI_genHash( "SHA1", pSecret, &binID );

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = binID.pVal;
    sTemplate[uCount].ulValueLen = binID.nLen;
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = pSecret->pVal;
    sTemplate[uCount].ulValueLen = pSecret->nLen;
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &kTrue;
    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createCertWithP11( JP11_CTX *pCTX, QString strName, const BIN *pID, const BIN *pCert )
{
    int rv = -1;
    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_CERTIFICATE_TYPE;
    sTemplate[uCount].pValue = &certType;
    sTemplate[uCount].ulValueLen = sizeof(certType);
    uCount++;

    BIN binSubject = {0,0};
    BIN binLabel = {0,0};

    if( !strName.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    if( pID )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = pID->pVal;
        sTemplate[uCount].ulValueLen = pID->nLen;
        uCount++;
    }

    rv = JS_PKI_getCertSubjetDN( pCert, &binSubject );
    if( rv == 0 )
    {
        sTemplate[uCount].type = CKA_SUBJECT;
        sTemplate[uCount].pValue = binSubject.pVal;
        sTemplate[uCount].ulValueLen = binSubject.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = pCert->pVal;
    sTemplate[uCount].ulValueLen = pCert->nLen;
    uCount++;

    JS_BIN_reset( &binSubject );
    JS_BIN_reset( &binLabel );

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binLabel );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create certificate(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createKeyPairWithP11( JP11_CTX *pCTX, const QString strName, const BIN *pPri )
{
    int rv = 0;
    BIN binID = {0,0};
    BIN binPub = {0,0};

    JRSAKeyVal  sRSAKey;
    JECKeyVal   sECKey;
    JDSAKeyVal  sDSAKey;
    JRawKeyVal  sRawKey;


    int nKeyType = JS_PKI_getPriKeyType( pPri );
    if( nKeyType < 0 ) return JSR_ERR;

    JS_PKI_getPubKeyFromPriKey( nKeyType, pPri, &binPub );
    JS_PKI_getKeyIdentifier( &binPub, &binID );

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));
    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sDSAKey, 0x00, sizeof(sDSAKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        rv = JS_PKI_getRSAKeyVal( pPri, &sRSAKey );
        if( rv != 0 ) goto end;

        rv = createRSAPrivateKeyP11( pCTX, strName, &binID, &sRSAKey );
        if( rv != 0 ) goto end;

        rv = createRSAPublicKeyP11( pCTX, strName, &binID, &sRSAKey );
        if( rv != 0 ) goto end;
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC || nKeyType == JS_PKI_KEY_TYPE_SM2 )
    {
        rv = JS_PKI_getECKeyVal( pPri, &sECKey );
        if( rv != 0 ) goto end;

        rv = createECPrivateKeyP11( pCTX, strName, &binID, &sECKey );
        if( rv != 0 ) goto end;

        rv = createECPublicKeyP11( pCTX, strName, &binID, &sECKey );
        if( rv != 0 ) goto end;
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        rv = JS_PKI_getDSAKeyVal( pPri, &sDSAKey );
        if( rv != 0 ) goto end;

        rv = createDSAPrivateKeyP11( pCTX, strName, &binID, &sDSAKey );
        if( rv != 0 ) goto end;

        rv = createDSAPublicKeyP11( pCTX, strName, &binID, &sDSAKey );
        if( rv != 0 ) goto end;
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ED25519 || nKeyType == JS_PKI_KEY_TYPE_ED448 )
    {
        rv = JS_PKI_getRawKeyVal( nKeyType, pPri, &sRawKey );
        if( rv != 0 ) goto end;

        rv = createEDPrivateKeyP11( pCTX, strName, &binID, &sRawKey );
        if( rv != 0 ) goto end;

        rv = createEDPublicKeyP11( pCTX, strName, &binID, &sRawKey );
        if( rv != 0 ) goto end;
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binPub );

    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
    JS_PKI_resetRawKeyVal( &sRawKey );

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

int createEDPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pRawKeyVal->pName;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strECPoints = pRawKeyVal->pPub;
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

int createEDPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal )
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

    QString strECParams = pRawKeyVal->pName;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strValue = pRawKeyVal->pPri;
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

int getHsmKeyList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& keyList )
{
    int rv = -1;

    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binKeyType = {0,0};


    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    CK_OBJECT_HANDLE hObjects[100];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;
/*
    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;
*/

    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, hObjects, 100, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_KEY_TYPE, &binKeyType );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binLabel, &pLabel );
        memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

        P11Rec P11Rec;
        P11Rec.setHandle( hObjects[i] );
        P11Rec.setLabel( pLabel );
        P11Rec.setKeyType( nKeyType );
        P11Rec.setID( getHexString( &binID ));

        keyList.append( P11Rec );

        JS_BIN_reset( &binLabel );
        JS_BIN_reset( &binKeyType );
        JS_BIN_reset( &binID );
        if( pLabel ) JS_free( pLabel );
    }

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binKeyType );
    JS_BIN_reset( &binID );

    return rv;
}

int getHsmPubList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& pubList )
{
    int rv = -1;

    BIN binLabel = {0,0};
    BIN binID = {0,0};
    BIN binKeyType = {0,0};


    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    CK_OBJECT_HANDLE hObjects[100];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;
/*
    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;
*/
    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, hObjects, 100, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_KEY_TYPE, &binKeyType );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binLabel, &pLabel );
        memcpy( &nKeyType, binKeyType.pVal, binKeyType.nLen );

        P11Rec P11Rec;
        P11Rec.setHandle( hObjects[i] );
        P11Rec.setLabel( pLabel );
        P11Rec.setKeyType( nKeyType );
        P11Rec.setID( getHexString( &binID ));

        pubList.append( P11Rec );

        JS_BIN_reset( &binLabel );
        JS_BIN_reset( &binKeyType );
        JS_BIN_reset( &binID );
        if( pLabel ) JS_free( pLabel );
    }

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binKeyType );
    JS_BIN_reset( &binID );

    return rv;
}

int getHsmCertList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& certList )
{
    int rv = -1;

    BIN binVal = {0,0};
    BIN binID = {0,0};
    BIN binLabel = {0,0};

    char *pLabel = NULL;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_KEY_TYPE keyType = CKK_DSA;

    CK_OBJECT_HANDLE hObjects[100];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, hObjects, 100, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

    for( int i = 0; i < uObjCnt; i++ )
    {
        char *pLabel = NULL;
        long nKeyType = -1;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_LABEL, &binLabel );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_VALUE, &binVal );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binLabel, &pLabel );

        P11Rec P11Rec;
        P11Rec.setHandle( hObjects[i] );
        P11Rec.setLabel( pLabel );
        P11Rec.setValue( getHexString( &binVal ) );
        P11Rec.setID( getHexString( &binID ));

        certList.append( P11Rec );

        JS_BIN_reset( &binLabel );
        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binID );
        if( pLabel ) JS_free( pLabel );
    }

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binID );

    if( pLabel ) JS_free( pLabel );

    return rv;
}

int getHsmKeyPairList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& pubList, QList<P11Rec>& priList )
{
    int rv = -1;

    BIN binVal = {0,0};
    BIN binID = {0,0};

    char *pLabel = NULL;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    CK_OBJECT_HANDLE hObjects[100];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, hObjects, 100, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

    for( int i = 0; i < uObjCnt; i++ )
    {
        CK_OBJECT_HANDLE hPriObj = -1;
        CK_ULONG uPriObjCnt = 0;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_LABEL, &binVal );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binVal, &pLabel );

        P11Rec PubRec;
        PubRec.setHandle( hObjects[i] );
        PubRec.setLabel( pLabel );

        JS_BIN_reset( &binVal );
        if( pLabel ) JS_free( pLabel );

        uCount = 0;
        objClass = CKO_PRIVATE_KEY;

        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &objClass;
        sTemplate[uCount].ulValueLen = sizeof(objClass);
        uCount++;

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;

        rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_FindObjects( pCTX, &hPriObj, 1, &uPriObjCnt );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_FindObjectsFinal( pCTX );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hPriObj, CKA_LABEL, &binVal );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binVal, &pLabel );

        P11Rec PriRec;
        PriRec.setHandle( hPriObj );
        PriRec.setLabel( pLabel );

        pubList.append( PubRec );
        priList.append( PriRec );

        JS_BIN_reset( &binID );
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binVal );
    if( pLabel ) JS_free( pLabel );

    return rv;
}

int getHsmPriCertList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& certList, QList<P11Rec>& priList )
{
    int rv = -1;

    BIN binVal = {0,0};
    BIN binID = {0,0};

    char *pLabel = NULL;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    CK_OBJECT_HANDLE hObjects[100];
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, hObjects, 100, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

    for( int i = 0; i < uObjCnt; i++ )
    {
        CK_OBJECT_HANDLE hPriObj = -1;
        CK_ULONG uPriObjCnt = 0;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_ID, &binID );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hObjects[i], CKA_LABEL, &binVal );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binVal, &pLabel );

        P11Rec PriRec;
        PriRec.setHandle( hObjects[i] );
        PriRec.setLabel( pLabel );

        JS_BIN_reset( &binVal );
        if( pLabel ) JS_free( pLabel );

        uCount = 0;
        objClass = CKO_CERTIFICATE;

        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &objClass;
        sTemplate[uCount].ulValueLen = sizeof(objClass);
        uCount++;

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;

        rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_FindObjects( pCTX, &hPriObj, 1, &uPriObjCnt );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_FindObjectsFinal( pCTX );
        if( rv != CKR_OK ) goto end;

        rv = JS_PKCS11_GetAttributeValue2( pCTX, hPriObj, CKA_LABEL, &binVal );
        if( rv != CKR_OK ) goto end;

        JS_BIN_string( &binVal, &pLabel );

        P11Rec CertRec;
        CertRec.setHandle( hPriObj );
        CertRec.setLabel( pLabel );

        certList.append( CertRec );
        priList.append( PriRec );

        JS_BIN_reset( &binID );
    }

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binVal );
    if( pLabel ) JS_free( pLabel );

    return rv;
}
