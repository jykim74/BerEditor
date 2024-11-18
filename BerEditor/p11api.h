#ifndef P11API_H
#define P11API_H

#include <QString>

#include "js_pki.h"
#include "js_pkcs11.h"
#include "js_error.h"

const QString kMechRSA = "RSA";
const QString kMechEC = "EC";
const QString kMechEdDSA = "EdDSA";
const QString kMechDSA = "DSA";
const QString kMechEd25519 = "Ed25519";
const QString kMechEd448 = "Ed448";
const QString kMechPKCS11_RSA = "PKCS11_RSA";
const QString kMechPKCS11_EC = "PKCS11_EC";
const QString kMechPKCS11_DSA = "PKCS11_DSA";


CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID, const QString strPIN = nullptr );
int genKeyPairWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub );

int createRSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createRSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createECPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pEcKeyVal );
int createECPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pECKeyVal );
int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );
int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );


#endif // P11API_H
