#include "js_kms.h"
#include "ttlv_encoder_dlg.h"
#include "js_pki.h"
#include "js_pkcs11.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h"

#include <QFileDialog>

const QStringList kTypeList = { "Object", "Cryptography", "Attribute" };
const QStringList kCmdObject =
    { kCMD_CREATE, kCMD_ACTIVATE, kCMD_GET, kCMD_DESTROY, kCMD_REGISTER, kCMD_LOCATE, kCMD_CREATE_KEY_PAIR };

const QStringList kCmdCryptography =
    { kCMD_ENCRYPT, kCMD_DECRYPT, kCMD_SIGN, kCMD_VERIFY, kCMD_HASH, kCMD_RNG_SEED, kCMD_RNG_RETRIEVE };

const QStringList kCmdAttribute =
    { kCMD_ADD_ATTRIBUTE, kCMD_GET_ATTRIBUTES, kCMD_MODIFY_ATTRIBUTE, kCMD_GET_ATTRIBUTE_LIST, kCMD_DELETE_ATTRIBUTE };

const QStringList kObjetType = { kOBJ_SECRET_KEY, kOBJ_PRIVATE_KEY, kOBJ_PUBLIC_KEY, kOBJ_CERTIFICATE };
const QStringList kAlgList = { kALG_RSA, kALG_ECDSA, kALG_AES };
const QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
const QStringList kECDSAOptionList = { "P-256", "P-384", "P-521" };
const QStringList kSymOptionList = { "16", "24", "32" };
const QStringList kSymModeList = { "ECB", "CBC", "CBC_PAD", "CTR", "CFB", "OFB" };
const QStringList kRSAModeList = { "V15", "V21" };


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

static int _getMech( int nAlg, QString strHash, QString strMode )
{
    if( nAlg == JS_PKI_KEY_TYPE_RSA )
    {
        if( strMode == "V21" )
        {
            if( strHash == "None" )
                return CKM_RSA_PKCS_PSS;
            else if( strHash == "SHA1" )
                return CKM_SHA1_RSA_PKCS_PSS;
            else if( strHash == "SHA224" )
                return CKM_SHA224_RSA_PKCS_PSS;
            else if( strHash == "SHA256" )
                return CKM_SHA256_RSA_PKCS_PSS;
            else if( strHash == "SHA384" )
                return CKM_SHA384_RSA_PKCS_PSS;
            else if( strHash == "SHA512" )
                return CKM_SHA512_RSA_PKCS_PSS;
            else
                return -1;
        }
        else
        {
            if( strHash == "None" )
                return CKM_RSA_PKCS;
            else if( strHash == "SHA1" )
                return CKM_SHA1_RSA_PKCS;
            else if( strHash == "SHA224" )
                return CKM_SHA224_RSA_PKCS;
            else if( strHash == "SHA256" )
                return CKM_SHA256_RSA_PKCS;
            else if( strHash == "SHA384" )
                return CKM_SHA384_RSA_PKCS;
            else if( strHash == "SHA512" )
                return CKM_SHA512_RSA_PKCS;
            else
                return -1;
        }
    }
    else if( nAlg == JS_PKI_KEY_TYPE_ECC )
    {
        if( strHash == "None" )
            return CKM_ECDSA;
        else if( strHash == "SHA1" )
            return CKM_ECDSA_SHA1;
        else if( strHash == "SHA224" )
            return CKM_ECDSA_SHA224;
        else if( strHash == "SHA256" )
            return CKM_ECDSA_SHA256;
        else if( strHash == "SHA384" )
            return CKM_ECDSA_SHA384;
        else if( strHash == "SHA512" )
            return CKM_ECDSA_SHA512;
        else
            return -1;
    }
    else if( nAlg == JS_PKI_KEY_TYPE_AES )
    {
        if( strHash == "None" )
            return CKM_AES_CMAC;
        else if( strHash == "SHA1" )
            return CKM_SHA_1_HMAC;
        else if( strHash == "SHA224" )
            return CKM_SHA224_HMAC;
        else if( strHash == "SHA256" )
            return CKM_SHA256_HMAC;
        else if( strHash == "SHA384" )
            return CKM_SHA384_HMAC;
        else if( strHash == "SHA512" )
            return CKM_SHA512_HMAC;
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

static int _getMechMode( int nAlg, const QString strMode )
{
    if( nAlg == JS_PKI_KEY_TYPE_AES )
    {
        if( strMode == "ECB" )
            return CKM_AES_ECB;
        else if( strMode == "CBC" )
            return CKM_AES_CBC;
        else if( strMode == "CBC_PAD" )
            return CKM_AES_CBC_PAD;
        else if( strMode == "CTR" )
            return CKM_AES_CTR;
        else if( strMode == "OFB" )
            return CKM_AES_OFB;
        else if( strMode == "CFB" )
            return CKM_AES_CFB128;
    }

    return -1;
}

TTLVEncoderDlg::TTLVEncoderDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mFindInputBtn, SIGNAL(clicked()), this, SLOT(findInput()));
    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType()));
    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmd()));
    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));

    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));
    connect( mObjectTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(objectTypeChanged(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mIVText, SIGNAL(textChanged(QString)), this, SLOT(changeIV()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(changeInput()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clearInput()));
    connect( mSignClearBtn, SIGNAL(clicked()), this, SLOT(clearSign()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clearOutput()));
    connect( mOutputDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeOutput()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clearAll()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mInputClearBtn->setFixedWidth(34);
    mSignClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
    mOutputDecodeBtn->setFixedWidth(34);

    mAuthGroup->layout()->setMargin(5);
    mAuthGroup->layout()->setSpacing(5);
    mInputGroup->layout()->setMargin(5);
    mInputGroup->layout()->setSpacing(5);
    mSignGroup->layout()->setMargin(5);
    mSignGroup->layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TTLVEncoderDlg::~TTLVEncoderDlg()
{

}

const QString TTLVEncoderDlg::getOutput()
{
    QString strOutput = mOutputText->toPlainText();
    return strOutput;
}

void TTLVEncoderDlg::initUI()
{
    mTypeCombo->addItems( kTypeList );
    mCmdCombo->addItems( kCmdObject );
    mIVTypeCombo->addItems( kValueTypeList );
    mInputTypeCombo->addItems( kValueTypeList );

    mObjectTypeCombo->addItems( kObjetType );
    mAlgCombo->addItems( kAlgList );
    mOptionCombo->addItems( kRSAOptionList );
    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText(berApplet->settingsMgr()->defaultHash());
    mAttributeCombo->addItems( kAttrList );
    mModeCombo->addItems( kRSAModeList );

    mSignText->setPlaceholderText( tr("Hex value" ));
    mOutputText->setPlaceholderText( tr("Hex value" ));
    mIVTypeCombo->setCurrentText( "String" );
    mIVText->setText( "0123456789ABCDEF" );
}

void TTLVEncoderDlg::initialize()
{
    changeCmd();
    changeIV();
}

void TTLVEncoderDlg::setEnableUUID( bool bVal )
{
    mUUIDLabel->setEnabled(bVal);
    mUUIDText->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableLen( bool bVal )
{
    mLenLabel->setEnabled(bVal);
    mLenText->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableAttribute( bool bVal )
{
    mAttributeLabel->setEnabled(bVal);
    mAttributeCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableObjectType( bool bVal )
{
    mObjectTypeLabel->setEnabled(bVal);
    mObjectTypeCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableAlg( bool bVal )
{
    mAlgLabel->setEnabled(bVal);
    mAlgCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableOption( bool bVal )
{
    mOptionLabel->setEnabled(bVal);
    mOptionCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableMode( bool bVal )
{
    mModeLabel->setEnabled(bVal);
    mModeCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableHash( bool bVal )
{
    mHashLabel->setEnabled(bVal);
    mHashCombo->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableIV( bool bVal )
{
    mIVLabel->setEnabled( bVal );
    mIVTypeCombo->setEnabled( bVal );
    mIVText->setEnabled( bVal );
    mIVLenText->setEnabled( bVal );
}

void TTLVEncoderDlg::setEnableInput( bool bVal )
{
    mInputGroup->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableSign( bool bVal )
{
    mSignGroup->setEnabled(bVal);
}

void TTLVEncoderDlg::setEnableAll( bool bVal )
{
    setEnableUUID(bVal);
    setEnableLen(bVal);
    setEnableAttribute(bVal);
    setEnableObjectType(bVal);
    setEnableAlg(bVal);
    setEnableOption(bVal);
    setEnableIV( bVal );
    setEnableHash(bVal);
    setEnableMode( bVal );
    setEnableInput(bVal);
    setEnableSign(bVal);
}

void TTLVEncoderDlg::changeType()
{
    QString strType = mTypeCombo->currentText();

    mCmdCombo->clear();

    if( strType == "Object" )
        mCmdCombo->addItems( kCmdObject );
    else if( strType == "Cryptography" )
        mCmdCombo->addItems( kCmdCryptography );
    else
        mCmdCombo->addItems( kCmdAttribute );
}

void TTLVEncoderDlg::changeCmd()
{
    QString strCmd = mCmdCombo->currentText();

    setEnableAll(false);

    if( strCmd == kCMD_GET || strCmd == kCMD_ACTIVATE || strCmd == kCMD_DESTROY )
    {
        setEnableUUID(true);
    }
    else if( strCmd == kCMD_CREATE )
    {
        setEnableAlg( true );
        setEnableOption( true );
        mAlgCombo->setCurrentText( kALG_AES );
    }
    else if( strCmd == kCMD_ENCRYPT || strCmd == kCMD_DECRYPT )
    {
        setEnableUUID(true);
        setEnableInput(true);
        setEnableIV(true);
        setEnableAlg(true);
        setEnableMode(true);
        mAlgCombo->setCurrentText( kALG_AES );
    }
    else if( strCmd == kCMD_SIGN )
    {
        setEnableUUID(true);
        setEnableInput(true);
        setEnableAlg(true);
        setEnableHash(true);
        setEnableMode(true);
        mAlgCombo->setCurrentText( kALG_RSA );
    }
    else if( strCmd == kCMD_VERIFY )
    {
        setEnableUUID(true);
        setEnableInput(true);
        setEnableSign(true);
        setEnableAlg(true);
        setEnableHash(true);
        setEnableMode(true);
        mAlgCombo->setCurrentText( kALG_RSA );
    }
    else if( strCmd == kCMD_HASH )
    {
        setEnableInput(true);
        setEnableHash(true);
    }
    else if( strCmd == kCMD_REGISTER )
    {
        setEnableInput(true);
        setEnableObjectType(true);
        setEnableOption( true );
        setEnableAlg(true);
    }
    else if( strCmd == kCMD_CREATE_KEY_PAIR )
    {
        setEnableAlg(true);
        setEnableOption(true);
        mAlgCombo->setCurrentText( kALG_RSA );
    }
    else if( strCmd == kCMD_GET_ATTRIBUTE_LIST )
    {
        setEnableUUID(true);
    }
    else if( strCmd == kCMD_ADD_ATTRIBUTE )
    {
        setEnableUUID(true);
        setEnableInput(true);
        setEnableAttribute(true);
    }
    else if( strCmd == kCMD_GET_ATTRIBUTES )
    {
        setEnableUUID(true);
    }
    else if( strCmd == kCMD_MODIFY_ATTRIBUTE )
    {
        setEnableUUID( true );
        setEnableAttribute( true );
        setEnableInput( true );
    }
    else if( strCmd == kCMD_DELETE_ATTRIBUTE )
    {
        setEnableUUID(true);
        setEnableAttribute( true );
    }
    else if( strCmd == kCMD_LOCATE )
    {
        setEnableAlg(true);
    }
    else if( strCmd == kCMD_RNG_RETRIEVE )
    {
        setEnableLen( true );
    }
    else if( strCmd == kCMD_RNG_SEED )
    {
        setEnableInput(true);
    }
    else if( strCmd == kCMD_HASH )
    {
        setEnableInput(true);
        setEnableHash( true );
    }
}

void TTLVEncoderDlg::clickEncode()
{
    QString strCmd = mCmdCombo->currentText();

    if( strCmd == kCMD_GET )
        clickGet();
    else if( strCmd == kCMD_ACTIVATE )
        clickActivate();
    else if( strCmd == kCMD_CREATE )
        clickCreate();
    else if( strCmd == kCMD_DESTROY )
        clickDestroy();
    else if( strCmd == kCMD_ENCRYPT )
        clickEncrypt();
    else if( strCmd == kCMD_DECRYPT )
        clickDecrypt();
    else if( strCmd == kCMD_SIGN )
        clickSign();
    else if( strCmd == kCMD_VERIFY )
        clickVerify();
    else if( strCmd == kCMD_HASH )
        clickHash();
    else if( strCmd == kCMD_REGISTER )
        clickRegister();
    else if( strCmd == kCMD_ADD_ATTRIBUTE )
        clickAddAttribute();
    else if( strCmd == kCMD_CREATE_KEY_PAIR )
        clickCreateKeyPair();
    else if( strCmd == kCMD_GET_ATTRIBUTE_LIST )
        clickGetAttributeList();
    else if( strCmd == kCMD_GET_ATTRIBUTES )
        clickGetAttributes();
    else if( strCmd == kCMD_MODIFY_ATTRIBUTE )
        clickModifyAttribute();
    else if( strCmd == kCMD_DELETE_ATTRIBUTE )
        clickDeleteAttribute();
    else if( strCmd == kCMD_LOCATE )
        clickLocate();
    else if( strCmd == kCMD_RNG_RETRIEVE )
        clickRNGRetrieve();
    else if( strCmd == kCMD_RNG_SEED )
        clickRNGSeed();
    else
    {
        berApplet->warnLog( tr( "Unknown Cmd: %1").arg( strCmd ), this );
    }
}

void TTLVEncoderDlg::algChanged( int index )
{
    QString strAlg = mAlgCombo->currentText();

    mOptionCombo->clear();
    mModeCombo->clear();

    if( strAlg == kALG_RSA )
    {
        mOptionLabel->setText( tr("KeyLength") );
        mOptionCombo->addItems(kRSAOptionList);
        mModeCombo->addItems( kRSAModeList );
    }
    else if( strAlg == kALG_ECDSA )
    {
        mOptionLabel->setText( tr("NamedCurve" ) );
        mOptionCombo->addItems(kECDSAOptionList);
    }
    else if( strAlg == kALG_AES )
    {
        mOptionLabel->setText( tr("KeyLength") );
        mOptionCombo->addItems( kSymOptionList );
        mModeCombo->addItems( kSymModeList );
    }
}

void TTLVEncoderDlg::objectTypeChanged( int index )
{
    QString strObjType = mObjectTypeCombo->currentText();

    if( strObjType == kOBJ_SECRET_KEY )
        mAlgCombo->setCurrentText( kALG_AES );
    else if( strObjType == kOBJ_PRIVATE_KEY || strObjType == kOBJ_PUBLIC_KEY )
        mAlgCombo->setCurrentText( kALG_RSA );
}

void TTLVEncoderDlg::findInput()
{
    BIN binFile = {0,0};
    char *pHex = NULL;

    QString strPath;
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );
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
    QString strUUID = mUUIDText->text();

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeGetReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickActivate()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeActivateReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickCreate()
{
    int ret = 0;
    BIN binData = {0,0};
    int nAlg = -1;
    int nKeyLen = -1;
    QString strAlg;

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    strAlg = mAlgCombo->currentText();

    if( strAlg == kALG_AES )
        nAlg = JS_PKI_KEY_TYPE_AES;
    else
    {
        berApplet->warningBox( tr( "Invalid algorith: %1" ).arg( strAlg ), this );
        goto end;
    }

    nKeyLen = mOptionCombo->currentText().toInt();

    ret = JS_KMS_encodeCreateReq( mAuthGroup->isChecked() ? &sAuth : NULL, nAlg, nKeyLen, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickDestroy()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeDestroyReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
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
    QString strIV = mIVText->text();

    Authentication sAuth = {0};
    int nMech = -1;
    int nAlg = -1;
    QString strAlg;
    QString strMode;

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    strAlg = mAlgCombo->currentText();

    getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
    getBINFromString( &binPlain, mInputTypeCombo->currentText(), strInput );

    if( strAlg == kALG_AES )
    {
        strMode = mModeCombo->currentText();
        nAlg = JS_PKI_KEY_TYPE_AES;
        nMech = _getMechMode( nAlg, strMode );
    }
    else if( strAlg == kALG_RSA )
    {
        strMode = mModeCombo->currentText();
        nAlg = JS_PKI_KEY_TYPE_RSA;

        if( strMode == "V21" )
            nMech = CKM_RSA_PKCS_OAEP;
        else
            nMech = CKM_RSA_PKCS;
    }
    else
    {
        berApplet->warningBox( tr( "Invalid algorithm: %1").arg( strAlg ), this );
        goto end;
    }

    ret = JS_KMS_encodeEncryptReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), nMech, &binIV, &binPlain, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPlain );
    JS_KMS_resetAuthentication( &sAuth );
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
    QString strIV = mIVText->text();

    Authentication sAuth = {0};
    int nMech = -1;
    int nAlg = -1;
    QString strAlg;
    QString strMode;

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
    getBINFromString( &binEncrypt, mInputTypeCombo->currentText(), strInput );

    if( strAlg == kALG_AES )
    {
        strMode = mModeCombo->currentText();
        nAlg = JS_PKI_KEY_TYPE_AES;
        nMech = _getMechMode( nAlg, strMode );
    }
    else if( strAlg == kALG_RSA )
    {
        strMode = mModeCombo->currentText();
        nAlg = JS_PKI_KEY_TYPE_RSA;

        if( strMode == "V21" )
            nMech = CKM_RSA_PKCS_OAEP;
        else
            nMech = CKM_RSA_PKCS;
    }
    else
    {
        berApplet->warningBox( tr( "Invalid algorithm: %1").arg( strAlg ), this );
        goto end;
    }

    ret = JS_KMS_encodeDecryptReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), nMech, &binIV, &binEncrypt, &binData );
    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binEncrypt );

    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickSign()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binPlain = {0};
    int nMech = 0;
    int nAlg = 0;

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();
    QString strAlg = mAlgCombo->currentText();
    QString strHash = mHashCombo->currentText();
    QString strMode = mModeCombo->currentText();

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    if( strAlg == kALG_RSA )
        nAlg = JS_PKI_KEY_TYPE_RSA;
    else if( strAlg == kALG_ECDSA )
        nAlg = JS_PKI_KEY_TYPE_ECC;
    else if( strAlg == kALG_AES )
        nAlg = JS_PKI_KEY_TYPE_AES;

    nMech = _getMech( nAlg, strHash, strMode );

    getBINFromString( &binPlain, mInputTypeCombo->currentText(), strInput );

    ret = JS_KMS_encodeSignReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), nMech, &binPlain, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_BIN_reset( &binPlain );
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickVerify()
{
    int ret = 0;
    int nAlg = 0;
    int nMech = 0;


    BIN binData = {0,0};

    BIN binPlain = {0};
    BIN binSign = {0};

    QString strUUID = mUUIDText->text();
    QString strInput = mInputText->toPlainText();
    QString strSign = mSignText->toPlainText();

    QString strAlg = mAlgCombo->currentText();
    QString strHash = mHashCombo->currentText();
    QString strMode = mModeCombo->currentText();

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }


    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    if( strSign.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a sign" ), this );
        mSignText->setFocus();
        goto end;
    }


    if( strAlg == kALG_RSA )
        nAlg = JS_PKI_KEY_TYPE_RSA;
    else if( strAlg == kALG_ECDSA )
        nAlg = JS_PKI_KEY_TYPE_ECC;
    else if( strAlg == kALG_AES )
        nAlg = JS_PKI_KEY_TYPE_AES;

    nMech = _getMech( nAlg, strHash, strMode );

    getBINFromString( &binPlain, mInputTypeCombo->currentText(), strInput );
    JS_BIN_decodeHex( strSign.toStdString().c_str(), &binSign );

    ret = JS_KMS_encodeVerifyReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), nMech, &binPlain, &binSign, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_BIN_reset( &binPlain );
    JS_BIN_reset( &binSign );

    JS_KMS_resetAuthentication( &sAuth );
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

    QString strObject = mObjectTypeCombo->currentText();
    QString strInput = mInputText->toPlainText();
    QString strAlg = mAlgCombo->currentText();
    QString strOption = mOptionCombo->currentText();

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    if( strObject == kOBJ_SECRET_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_SECRET;
    }
    else if( strObject == kOBJ_PRIVATE_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_PRIKEY;
    }
    else if( strObject == kOBJ_PUBLIC_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_PUBKEY;
    }
    else if( strObject == kOBJ_CERTIFICATE )
    {
        nType = JS_KMS_OBJECT_TYPE_CERT;
    }

    getBINFromString( &binInput, mInputTypeCombo->currentText(), strInput );

    if( strAlg == kALG_RSA )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = strOption.toInt();

        if( nType == JS_KMS_OBJECT_TYPE_SECRET )
        {
            berApplet->warningBox( tr("ObjectType[%1] and Algorithm[%2] do not match").arg(strObject).arg( strAlg ), this );
            goto end;
        }
    }
    else if( strAlg == kALG_ECDSA )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;

        if( strOption == "P-256")
            nParam = KMIP_CURVE_P_256;
        else if( strOption == "P-384" )
            nParam = KMIP_CURVE_P_384;
        else if( strOption == "P-521" )
            nParam = KMIP_CURVE_P_521;

        if( nType == JS_KMS_OBJECT_TYPE_SECRET )
        {
            berApplet->warningBox( tr("ObjectType[%1] and Algorithm[%2] do not match").arg(strObject).arg( strAlg ), this );
            goto end;
        }
    }
    else if( strAlg == kALG_AES )
    {
        nAlg = JS_PKI_KEY_TYPE_AES;
        nParam = strOption.toInt();

        if( nType != JS_KMS_OBJECT_TYPE_SECRET )
        {
            berApplet->warningBox( tr("ObjectType[%1] and Algorithm[%2] do not match").arg(strObject).arg( strAlg ), this );
            goto end;
        }
    }

    ret = JS_KMS_encodeRegisterReq( mAuthGroup->isChecked() ? &sAuth : NULL, nAlg, nParam, nType, &binInput, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_BIN_reset( &binInput );
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickCreateKeyPair()
{
    int ret = 0;
    int nAlg = -1;
    int nParam = 2048;
    QString strAlg;

    BIN binData = {0,0};

    Authentication sAuth = {0};
    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    strAlg = mAlgCombo->currentText();

    if( strAlg == kALG_RSA )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = mOptionCombo->currentText().toInt();
    }
    else if( strAlg == kALG_ECDSA )
    {
        QString strOption = mAlgCombo->currentText();
        nAlg = JS_PKI_KEY_TYPE_ECC;

        if( strOption == "P-256")
            nParam = KMIP_CURVE_P_256;
        else if( strOption == "P-384" )
            nParam = KMIP_CURVE_P_384;
        else if( strOption == "P-521" )
            nParam = KMIP_CURVE_P_521;
    }
    else
    {
        berApplet->warningBox( tr( "Invalid algorith: %1" ).arg( strAlg ), this );
        goto end;
    }

    ret = JS_KMS_encodeCreateKeyPairReq( mAuthGroup->isChecked() ? &sAuth : NULL, nAlg, nParam, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickGetAttributeList()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeGetAttributeListReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
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

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strAttrValue.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter the attribute value into the input field." ), this );
        mInputText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeAddAttributeReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), strAttrValue.toStdString().c_str(), &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickGetAttributes()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeGetAttributesReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), NULL, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
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

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    if( strAttrValue.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter the attribute value into the input field." ), this );
        mInputText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeModifyAttributeReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), strAttrValue.toStdString().c_str(), &binData );
    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickDeleteAttribute()
{
    int ret = 0;
    BIN binData = {0,0};

    QString strUUID = mUUIDText->text();
    QString strAttrName = mAttributeCombo->currentText();

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strUUID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a UUID" ), this );
        mUUIDText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeDeleteAttributeReq( mAuthGroup->isChecked() ? &sAuth : NULL, strUUID.toStdString().c_str(), strAttrName.toStdString().c_str(), 0, &binData );
    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickLocate()
{
    int ret = 0;
    int nAlg = -1;

    BIN binData = { 0, 0};

    Authentication sAuth = {0};
    QString strAlg = mAlgCombo->currentText();

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strAlg == kALG_RSA )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
    }
    else if( strAlg == kALG_ECDSA )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;
    }
    else if( strAlg == kALG_AES )
    {
        nAlg = JS_PKI_KEY_TYPE_AES;
    }

    ret = JS_KMS_encodeLocateReq( mAuthGroup->isChecked() ? &sAuth : NULL, nAlg, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickRNGRetrieve()
{
    int ret = 0;
    int nLen = mLenText->text().toInt();
    BIN binData = {0,0};

    Authentication sAuth = {0};

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( nLen <= 0 )
    {
        berApplet->warningBox( tr( "Enter a length" ), this );
        mLenText->setFocus();
        goto end;
    }

    ret = JS_KMS_encodeRNGRetrieveReq( mAuthGroup->isChecked() ? &sAuth : NULL, nLen, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickRNGSeed()
{
    int ret = 0;
    BIN binSrc = {0};
    BIN binData = {0,0};

    Authentication sAuth = {0};
    QString strInput = mInputText->toPlainText();

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    getBINFromString( &binSrc, mInputTypeCombo->currentText(), strInput );

    ret = JS_KMS_encodeRNGSeedReq( mAuthGroup->isChecked() ? &sAuth : NULL, &binSrc, &binData );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clickHash()
{
    int ret = 0;
    BIN binSrc = {0};
    BIN binData = {0,0};
    int nMech = -1;

    QString strHash = mHashCombo->currentText();
    QString strInput = mInputText->toPlainText();

    Authentication sAuth = {0};
    if( mAuthGroup->isChecked() == true )
    {
        QString strUserID = mUserIDText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserID.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a UserID" ), this );
            mUserIDText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }

        JS_KMS_makeAuthentication( strUserID.toStdString().c_str(), strPasswd.toStdString().c_str(), &sAuth );
    }

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a input" ), this );
        mInputText->setFocus();
        goto end;
    }

    nMech = _getMechHash( strHash );

    getBINFromString( &binSrc, mInputTypeCombo->currentText(), strInput );

    ret = JS_KMS_encodeHashReq( mAuthGroup->isChecked() ? &sAuth : NULL, nMech, &binSrc, &binData );
    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binData ));
    }
    else
    {
        berApplet->warningBox( tr( "fail to encode TTLV: %1").arg( ret ), this );
    }

end :
    JS_KMS_resetAuthentication( &sAuth );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::changeIV()
{
    QString strIV = mIVText->text();
    QString strLen = getDataLenString( mIVTypeCombo->currentText(), strIV );
    mIVLenText->setText( QString("%1").arg( strLen ));
}

void TTLVEncoderDlg::changeInput()
{
    QString strInput = mInputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strInput );
    mInputLenText->setText( QString("%1").arg( strLen ));
}

void TTLVEncoderDlg::changeSign()
{
    QString strSign = mSignText->toPlainText();
    QString strLen = getDataLenString( mInputTypeCombo->currentText(), strSign );
    mSignLenText->setText( QString("%1").arg( strLen ));
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

void TTLVEncoderDlg::clearSign()
{
    mSignText->clear();
}

void TTLVEncoderDlg::clearOutput()
{
    mOutputText->clear();
}

void TTLVEncoderDlg::decodeOutput()
{
    BIN binData = {0,0};
    QString strOutput = mOutputText->toPlainText();

    getBINFromString( &binData, DATA_HEX, strOutput );
    berApplet->decodeTTLV( &binData );
    JS_BIN_reset( &binData );
}

void TTLVEncoderDlg::clearAll()
{
    mUUIDText->clear();
    mLenText->clear();

    clearInput();
    clearSign();
    clearOutput();
}
