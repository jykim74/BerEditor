#ifndef P11API_H
#define P11API_H

#include <QString>
#include <QList>

#include "js_pki.h"
#include "js_pkcs11.h"
#include "js_error.h"
#include "p11_rec.h"

enum DeviceType {
    DeviceHDD = 0,
    DeviceHSM
};


static CK_BBOOL kTrue = CK_TRUE;
static CK_BBOOL kFalse = CK_FALSE;

//PrintableString curve25519
static unsigned char kCurveNameX25519[] = { 0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39 };
static unsigned char kOID_X25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x6E };

//PrintableString cruve448
static unsigned char kCurveNameX448[] = { 0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38 };
static unsigned char kOID_X448[] = { 0x06, 0x03, 0x2B, 0x65, 0x6F };


long getP11KeyType( const QString strAlg );
const QString getP11KeyTypeName( long uKeyType );

long getHandleHSM( JP11_CTX *pCTX, CK_OBJECT_CLASS objClass, const BIN *pID );
int getID_HSM( JP11_CTX *pCTX, CK_OBJECT_HANDLE hObj, BIN *pID );
int getCertHSM( JP11_CTX *pCTX, CK_OBJECT_HANDLE hObj, BIN *pCert );

int loadPKCS11Libray( const QString strLibPath, JP11_CTX **ppCTX );
int getP11Session( void *pP11CTX, int nSlotIndex = 0 );
int getP11SessionLogin( void *pP11CTX, int nSlotIndex, const QString strPIN = nullptr );

int genKeyWithP11( JP11_CTX *pCTX, QString strName, QString strAlg );
int genKeyPairWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub );
int createKeyWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, const BIN *pID, const BIN *pSecret );
int createCertWithP11( JP11_CTX *pCTX, QString strName, const BIN *pID, const BIN *pCert );
int createKeyPairWithP11( JP11_CTX *pCTX, const QString strName, const BIN *pPri );

int createRSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createRSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createECPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pEcKeyVal );
int createECPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pECKeyVal );
int createEDPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal );
int createEDPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal );
int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );
int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );

int getHsmKeyList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& keyList );
int getHsmPubList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& pubList );
int getHsmCertList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& certList );
int getHsmKeyPairList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& pubList, QList<P11Rec>& priList );
int getHsmPriCertList( JP11_CTX *pCTX, const QString strAlg, QList<P11Rec>& certList, QList<P11Rec>& priList );


int getRSAPublicKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );
int getECPublicKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );
int getDSAPublicKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );
int getEDPublicKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );

int getPublicKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );

int getRSAPrivateKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPriKey );
int getECPrivateKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPriKey );
int getDSAPrivateKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPriKey );
int getEDPrivateKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPubKey );

int getPrivateKeyHSM( JP11_CTX *pCTX, long hObject, BIN *pPriKey );

#endif // P11API_H
