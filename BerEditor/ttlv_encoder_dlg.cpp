#include "js_kms.h"
#include "ttlv_encoder_dlg.h"
#include "js_pki.h"
#include "js_pkcs11.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h"

#include <QFileDialog>

const QStringList kObjetType = { "SecretKey", "PrivateKey", "PublicKey", "Certificate" };
const QStringList kAlgList = { "RSA", "ECDSA", "AES" };
const QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
const QStringList kECDSAOptionList = { "P-256" };


/*
const QStringList kAttrList = { "",
    "Unique Identifier", "Name", "Object Type",
    "Cryptographic Algorithm", "Cryptographic Length", "Cryptographic Parameters", "Cryptographic Domain Parameters",
    "Certificate Type", "Certificate Length", "X.509 Certificate Identifier", "X.509 Certificate Subject",
    "X.509 Certificate Issuer", "Certificate Identifier", "Certificate Subject", "Certificate Issuer",
    "Digital Signature Algorithm", "Digest", "Operation Policy Name", "Cryptographic Usage Mask",
    "Lease Time", "Usage Limits", "State", "Initial Date",
    "Activation Date", "Process Start Date", "Protect Stop Date", "Deactivation Date",
    "Destroy Date", "Compromise Occurrence Date", "Compromise Date", "Revocation Reason",
    "Archive Date", "Object Group", "Fresh", "Link",
    "Application Specific Information", "Contact Information", "Last Change Date",
    "Custom Attribute", "Alternative Name", "Key Value Present", "Key Value Location",
    "Original Creation Date", "Sensitive"
};
*/

const QStringList kAttrList = { "",
                                "Unique Identifier",
                                "Name",
                                "Object Type",
                                "Cryptographic Algorithm",
                                "Cryptographic Length",
                                "Operation Policy Name",
                                "Cryptographic Usage Mask",
                                "State",
                                "Initial Date",
};

static int _getMech( int nAlg, QString strHash )
{
    if( nAlg == JS_PKI_KEY_TYPE_RSA )
    {
        if( strHash == "None" )
            return CKM_RSA_PKCS;
        else if( strHash == "SHA1" )
            return CKM_SHA1_RSA_PKCS;
        else if( strHash == "SHA256" )
            return CKM_SHA256_RSA_PKCS;
        else if( strHash == "SHA384" )
            return CKM_SHA384_RSA_PKCS;
        else if( strHash == "SHA512" )
            return CKM_SHA512_RSA_PKCS;
        else
            return -1;
    }
    else if( nAlg == JS_PKI_KEY_TYPE_ECC )
    {
        if( strHash == "None" )
            return CKM_ECDSA;
        else if( strHash == "SHA1" )
            return CKM_ECDSA_SHA1;
        else if( strHash == "SHA256" )
            return CKM_ECDSA_SHA256;
        else if( strHash == "SHA384" )
            return CKM_ECDSA_SHA384;
        else if( strHash == "SHA512" )
            return CKM_ECDSA_SHA512;
        else
            return -1;
    }

    return -1;
}

static int _getMechHash( QString strHash )
{
    if( strHash == "SHA1" )
        return CKM_SHA_1;
    else if( strHash == "SHA256" )
        return CKM_SHA256;
    else if( strHash == "SHA384" )
        return CKM_SHA384;
    else if( strHash == "SHA512" )
        return CKM_SHA512;
    else
        return -1;
}

TTLVEncoderDlg::TTLVEncoderDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mFindInputBtn, SIGNAL(clicked()), this, SLOT(findInput()));

    connect( mCreateBtn, SIGNAL(clicked()), this, SLOT(clickCreate()));
    connect( mActivateBtn, SIGNAL(clicked()), this, SLOT(clickActivate()));
    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(clickGet()));
    connect( mDestroyBtn, SIGNAL(clicked()), this, SLOT(clickDestroy()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mSignBtn, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mRegisterBtn, SIGNAL(clicked()), this, SLOT(clickRegister()));
    connect( mCreateKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCreateKeyPair()));

    connect( mGetAttributeListBtn, SIGNAL(clicked()), this, SLOT(clickGetAttributeList()));
    connect( mAddAttributeBtn, SIGNAL(clicked()), this, SLOT(clickAddAttribute()));
    connect( mGetAttributes, SIGNAL(clicked()), this, SLOT(clickGetAttributes()));
    connect( mModifyAttributeBtn, SIGNAL(clicked()), this, SLOT(clickModifyAttribute()));
    connect( mDeleteAttributeBtn, SIGNAL(clicked()), this, SLOT(clickDeleteAttribute()));
    connect( mLocateBtn, SIGNAL(clicked()), this, SLOT(clickLocate()));
    connect( mRNGRetrieveBtn, SIGNAL(clicked()), this, SLOT(clickRNGRetrieve()));
    connect( mRNGSeedBtn, SIGNAL(clicked()), this, SLOT(clickRNGSeed()));
    connect( mHashBtn, SIGNAL(clicked()), this, SLOT(clickHash()));

    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clearInput()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clearOutput()));

    initialize();
    mCreateBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mInputClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TTLVEncoderDlg::~TTLVEncoderDlg()
{

}

void TTLVEncoderDlg::initialize()
{
    mObjectTypeCombo->addItems( kObjetType );
    mAlgCombo->addItems( kAlgList );
    mOptionCombo->addItems( kRSAOptionList );
    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText(berApplet->settingsMgr()->defaultHash());
    mAttributeCombo->addItems( kAttrList );
}

void TTLVEncoderDlg::algChanged( int index )
{
    mOptionCombo->clear();

   if( index == 0 )
   {
       mOptionLabel->setText( tr("KeyLength") );
       mOptionCombo->addItems(kRSAOptionList);
   }
   else
   {
       mOptionLabel->setText( tr("NamedCurve" ) );
       mOptionCombo->addItems(kECDSAOptionList);
   }
}
void TTLVEncoderDlg::findInput()
{
    BIN binFile = {0,0};
    char *pHex = NULL;

    QString strPath = QDir::currentPath();
    QString fileName = findFile( this, JS_FILE_TYPE_ALL, strPath );
    if( fileName.isEmpty() ) return;

    JS_BIN_fileRead( fileName.toStdString().c_str(), &binFile );
    JS_BIN_encodeHex( &binFile, &pHex );

    if( pHex )
    {
        mInputText->setPlainText( pHex );
        JS_free( pHex );
    }

    JS_BIN_reset( &binFile );
}


void TTLVEncoderDlg::clickGet()
{
    int ret = 0;
    BIN binData = {0,0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    QString strUUID = mUUIDText->text();

    ret = JS_KMS_encodeGetReq( &sAuth, strUUID.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickActivate()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    ret = JS_KMS_encodeActivateReq( &sAuth, strUUID.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickCreate()
{
    int ret = 0;
    BIN binData = {0,0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeCreateReq( &sAuth, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickDestroy()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );
    ret = JS_KMS_encodeDestroyReq( &sAuth, strUUID.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickEncrypt()
{
    int ret = 0;
    BIN binData = {0,0};

    BIN binIV = {0};
    BIN binPlain = {0};

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    JS_BIN_set( &binIV, (unsigned char *)"1234567890123456", 16);
    JS_BIN_set( &binPlain, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );

    ret = JS_KMS_encodeEncryptReq( &sAuth, strUUID.toStdString().c_str(), &binIV, &binPlain, &binData );

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPlain );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickDecrypt()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binIV = {0};
    BIN binEncrypt = {0};

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    JS_BIN_set( &binIV, (unsigned char *)"1234567890123456", 16);
    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binEncrypt );

    ret = JS_KMS_encodeDecryptReq( &sAuth, strUUID.toStdString().c_str(), &binIV, &binEncrypt, &binData );

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binEncrypt );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickSign()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binPlain = {0};
    int nMech = 0;
    int nAlg = 0;
    QString strHash;

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    if( mAlgCombo->currentIndex() == 0 )
        nAlg = JS_PKI_KEY_TYPE_RSA;
    else if( mAlgCombo->currentIndex() == 1 )
        nAlg = JS_PKI_KEY_TYPE_ECC;

    strHash = mHashCombo->currentText();

    nMech = _getMech( nAlg, strHash );

    JS_BIN_set( &binPlain, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );

    ret = JS_KMS_encodeSignReq( &sAuth, strUUID.toStdString().c_str(), nMech, &binPlain, &binData );

    JS_BIN_reset( &binPlain );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickVerify()
{
    int ret = 0;
    int nAlg = 0;
    int nMech = 0;
    QString strHash;

    BIN binData = {0,0};

    BIN binPlain = {0};
    BIN binSign = {0};

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    if( mAlgCombo->currentIndex() == 0 )
        nAlg = JS_PKI_KEY_TYPE_RSA;
    else if( mAlgCombo->currentIndex() == 1 )
        nAlg = JS_PKI_KEY_TYPE_ECC;

    strHash = mHashCombo->currentText();

    nMech = _getMech( nAlg, strHash );

    JS_BIN_set( &binPlain, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    JS_BIN_decodeHex( strOutput.toStdString().c_str(), &binSign );

    ret = JS_KMS_encodeVerifyReq( &sAuth, strUUID.toStdString().c_str(), nMech, &binPlain, &binSign, &binData );

    JS_BIN_reset( &binPlain );
    JS_BIN_reset( &binSign );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickRegister()
{
    int ret = 0;
    int nAlg = 0;
    int nParam = 0;
    BIN binData = {0,0};

    int nType = 0;
    BIN binInput = {0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    QString strInput = mInputText->toPlainText();

    if( mObjectTypeCombo->currentIndex() == 0 )
        nType = JS_KMS_OBJECT_TYPE_SECRET;
    else if( mObjectTypeCombo->currentIndex() == 1 )
        nType = JS_KMS_OBJECT_TYPE_PRIKEY;
    else if( mObjectTypeCombo->currentIndex() == 2 )
        nType = JS_KMS_OBJECT_TYPE_PUBKEY;
    else if( mObjectTypeCombo->currentIndex() == 3 )
        nType = JS_KMS_OBJECT_TYPE_CERT;

    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );

    if( mAlgCombo->currentIndex() == 0 )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = mOptionCombo->currentText().toInt();
    }
    else if( mAlgCombo->currentIndex() == 1 )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;
        nParam = KMIP_CURVE_P_256;
    }

    ret = JS_KMS_encodeRegisterReq( &sAuth, nAlg, nParam, nType, &binInput, &binData );

    JS_BIN_reset( &binInput );
    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickCreateKeyPair()
{
    int ret = 0;
    int nAlg = -1;
    int nParam = 2048;

    BIN binData = {0,0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    if( mAlgCombo->currentIndex() == 0 )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = mOptionCombo->currentText().toInt();
    }
    else if( mAlgCombo->currentIndex() == 1 )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;
        nParam = KMIP_CURVE_P_256;
    }

    ret = JS_KMS_encodeCreateKeyPairReq( &sAuth, nAlg, nParam, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickGetAttributeList()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    ret = JS_KMS_encodeGetAttributeListReq( &sAuth, strUUID.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickAddAttribute()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    QString strAttrName = mAttributeCombo->currentText();
    QString strAttrValue = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeAddAttributeReq( &sAuth, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), strAttrValue.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickGetAttributes()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    ret = JS_KMS_encodeGetAttributesReq( &sAuth, strUUID.toStdString().c_str(), NULL, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickModifyAttribute()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    QString strAttrName = mAttributeCombo->currentText();
    QString strAttrValue = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeModifyAttributeReq( &sAuth, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), strAttrValue.toStdString().c_str(), &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickDeleteAttribute()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    QString strAttrName = mAttributeCombo->currentText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeDeleteAttributeReq( &sAuth, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), 0, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickLocate()
{
    int ret = 0;
    int nAlg = -1;

    BIN binData = { 0, 0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    if( mAlgCombo->currentIndex() == 0 )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
    }
    else if( mAlgCombo->currentIndex() == 1 )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;
    }
    else if( mAlgCombo->currentIndex() == 2 )
    {
        nAlg = JS_PKI_KEY_TYPE_AES;
    }

    ret = JS_KMS_encodeLocateReq( &sAuth, nAlg, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickRNGRetrieve()
{
    int ret = 0;
    int nLen = mLenText->text().toInt();
    BIN binData = {0,0};

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeRNGRetrieveReq( &sAuth, nLen, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickRNGSeed()
{
    int ret = 0;
    BIN binSrc = {0};
    BIN binData = {0,0};

    QString strInput = mInputText->toPlainText();
    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );

    ret = JS_KMS_encodeRNGSeedReq( &sAuth, &binSrc, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickHash()
{
    int ret = 0;
    BIN binSrc = {0};
    BIN binData = {0,0};

    QString strHash = mHashCombo->currentText();
    QString strInput = mInputText->toPlainText();

    Authentication sAuth = {0};
    JS_KMS_makeAuthentication( mUserIDText->text().toStdString().c_str(), mPasswdText->text().toStdString().c_str(), &sAuth );


    int nMech = _getMechHash( strHash );

    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );

    ret = JS_KMS_encodeHashReq( &sAuth, nMech, &binSrc, &binData );

    JS_KMS_resetAuthentication( &sAuth );

    if( ret == 0 )
    {
        berApplet->decodeTTLV( &binData );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ) );
    }

    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::changeInput()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strInput );
    mInputLenText->setText( QString("%1").arg( strLen ));
}

void TTLVEncoderDlg::changeOutput()
{
    QString strOutput = mOutputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg( strLen ));
}

void TTLVEncoderDlg::clearInput()
{
    mInputText->clear();
}

void TTLVEncoderDlg::clearOutput()
{
    mOutputText->clear();
}
