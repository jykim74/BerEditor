#include <QFile>
#include <QTextStream>

#include "key_add_dlg.h"
#include "ui_key_add_dlg.h"
#include "ber_applet.h"
#include "common.h"
#include "settings_mgr.h"
#include "new_passwd_dlg.h"
#include "passwd_dlg.h"

#include "js_error.h"
#include "js_pki.h"
#include "js_pkcs11.h"
#include "p11api.h"

static const QStringList kTypeList = { "AES", "ARIA", "SEED", "TDES", "HMAC" };

KeyAddDlg::KeyAddDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mHsmCheck, SIGNAL(clicked()), this, SLOT(checkHSM()));

    connect( mRandKeyBtn, SIGNAL(clicked()), this, SLOT(clickRandKey()));

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKeyType()));
    connect( mIVTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeIVType()));

    connect( mKeyText, SIGNAL(textChanged(QString)), this, SLOT(changeKeyType()));
    connect( mIVText, SIGNAL(textChanged(QString)), this, SLOT(changeIVType()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    mOKBtn->setDefault(true);

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyAddDlg::~KeyAddDlg()
{

}

int KeyAddDlg::readFile( const QString strName )
{
    int ret = 0;
    QString strPath = berApplet->settingsMgr()->keyListPath();
    QString strFilePath = QString( "%1/%2" ).arg( strPath ).arg( strName );

    QFile keyFile( strFilePath );

    if( keyFile.open( QIODevice::ReadOnly | QIODevice::Text ) == false )
    {
        berApplet->elog( QString( "fail to read key: %1" ).arg( strFilePath ));
        return JSR_ERR;
    }

    QString strAlg;
    QString strKey;
    QString strIV;
    QString strData;

    QTextStream in( &keyFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        if( strLine.length() < 2 || strLine.at(0) == '#' )
        {
            strLine = in.readLine();
            continue;
        }

        QStringList nameVal = strLine.split(":");
        if( nameVal.size() < 2 )
        {
            strLine = in.readLine();
            continue;
        }

        QString strFirst = nameVal.at(0).simplified();
        QString strSecond = nameVal.at(1).simplified();

        if( strFirst == "ALG" )
            strAlg = strSecond;
        else if( strFirst == "Key" )
            strKey = strSecond;
        else if( strFirst == "IV" )
            strIV = strSecond;

        strLine = in.readLine();
    }

    keyFile.close();

    if( strKey.contains( "{ENC}" ) == true )
    {
        PasswdDlg passDlg;
        QString strPasswd;
        QString strValue = strKey.mid(5);

        BIN binEnc = {0,0};
        BIN binKey = {0,0};

        if( passDlg.exec() != QDialog::Accepted )
            return JSR_ERR2;

        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binEnc );

        strPasswd = passDlg.mPasswdText->text();
        ret = getUnwrapKey( strPasswd.toStdString().c_str(), &binEnc, &binKey );
        strKey = getHexString( &binKey );
        JS_BIN_reset( &binEnc );
        JS_BIN_reset( &binKey );

        if( ret != 0 )
        {
            ret = JSR_PASSWORD_WRONG;
            return ret;
        }
    }

    mTypeCombo->clear();
    mKeyLenCombo->clear();
    mKeyTypeCombo->clear();
    mIVTypeCombo->clear();

    disconnect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( changeType() ) );

    mKeyTypeCombo->addItem( "Hex" );
    mIVTypeCombo->addItem( "Hex" );

    mTypeCombo->addItem( strAlg );
    mKeyLenCombo->addItem( QString( "%1" ).arg( strKey.length() / 2) );
    mNameText->setText( strName );
    mKeyText->setText( strKey );
    mIVText->setText( strIV );

    return 0;
}

int KeyAddDlg::setHSM( long hObject )
{
    int rv = 0;
    BIN binVal = {0,0};
    BIN binLabel = {0,0};
    BIN binLen = {0,0};
    BIN binType = {0,0};

    char *pLabel = NULL;

    JP11_CTX *pCTX = berApplet->getP11CTX();
    int nIndex = berApplet->settingsMgr()->hsmIndex();
    int nKeyLen = 0;
    int nKeyType = 0;

    rv = getP11SessionLogin( pCTX, nIndex );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_GetAttributeValue2( pCTX, hObject, CKA_LABEL, &binLabel );
    if( rv != CKR_OK ) goto end;

    JS_BIN_string( &binLabel, &pLabel );

    mTypeCombo->clear();
    mKeyLenCombo->clear();
    mKeyTypeCombo->clear();
    mIVTypeCombo->clear();

    rv = JS_PKCS11_GetAttributeValue2( pCTX, hObject, CKA_VALUE, &binVal );
    if( rv == CKR_OK )
    {
        mKeyText->setText( getHexString( &binVal ));
        mKeyTypeCombo->addItem( "Hex" );
    }
    else
    {
        mKeyTypeCombo->addItem( "String" );
        mKeyText->setText( QString("%1").arg( pCTX->sLastLog ));
    }

    rv = JS_PKCS11_GetAttributeValue2( pCTX, hObject, CKA_VALUE_LEN, &binLen );

    if( binLen.nLen > 0 ) memcpy( &nKeyLen, binLen.pVal, binLen.nLen );

    rv = JS_PKCS11_GetAttributeValue2( pCTX, hObject, CKA_KEY_TYPE, &binType );

    if( binType.nLen > 0 ) memcpy( &nKeyType, binType.pVal, binType.nLen );

    mHsmCheck->setChecked(true);
    checkHSM();

    mNameText->setText( pLabel );

    mKeyLenCombo->addItem( QString("%1").arg( nKeyLen ));
    mTypeCombo->addItem( QString( "%1").arg( getP11KeyTypeName( nKeyType )));

end :
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binLen );
    JS_BIN_reset( &binType );

    if( pLabel ) JS_free( pLabel );

    return rv;
}

void KeyAddDlg::setReadOnly()
{
    mRandKeyBtn->setEnabled(false);

    mNameText->setReadOnly(true);
    mKeyText->setReadOnly(true);
    mKeyText->setStyleSheet(kReadOnlyStyle);
    mIVText->setReadOnly(true);
    mIVText->setStyleSheet(kReadOnlyStyle);

    mClearAllBtn->hide();
    mOKBtn->hide();
}

void KeyAddDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void KeyAddDlg::initUI()
{
    mTypeCombo->addItems( kTypeList );

    mKeyTypeCombo->addItems( kValueTypeList );
    mIVTypeCombo->addItems( kValueTypeList );
}

void KeyAddDlg::initialize()
{

}

void KeyAddDlg::clickClearAll()
{
    mNameText->clear();
    mKeyText->clear();
    mIVText->clear();
}

void KeyAddDlg::clickOK()
{
    int ret = 0;
    QString strName = mNameText->text();
    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    BIN binKey = {0,0};
    BIN binIV = {0,0};

    BIN binWrapKey = {0,0};

    int nLen = mKeyLenCombo->currentText().toInt();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    if( strKey.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a key" ), this );
        mKeyText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );

    if( nLen > 0 && nLen != binKey.nLen )
    {
        berApplet->warningBox( tr( "Key Length is not %1 bytes").arg( nLen ), this );
        ret = -1;
        goto end;
    }

    if( mEncCheck->isChecked() == true )
    {
        NewPasswdDlg newPass;
        if( newPass.exec() != QDialog::Accepted )
        {
            ret = JSR_ERR;
            goto end;
        }

        QString strPasswd = newPass.mPasswdText->text();

        ret = getWrapKey( strPasswd.toStdString().c_str(), &binKey, &binWrapKey );
        if( ret != 0 ) goto end;

        res_key_ = QString( "{ENC}%1").arg( getHexString( &binWrapKey ));
    }
    else
    {
        res_key_ = getHexString( &binKey );
    }

    ret = 0;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binWrapKey );

    if( ret == 0 ) accept();
}

void KeyAddDlg::checkHSM()
{
    bool bVal = mHsmCheck->isChecked();

    mEncCheck->setEnabled( !bVal );
    mIVText->setEnabled( !bVal );
    mIVTypeCombo->setEnabled( !bVal );
    mIVLenText->setEnabled( !bVal );
}

void KeyAddDlg::clickRandKey()
{
    BIN binRand = {0,0};
    int nLen = mKeyLenCombo->currentText().toInt();

    if( nLen > 0 )
    {
        JS_PKI_genRandom( nLen, &binRand );
        mKeyTypeCombo->setCurrentText( "Hex" );
        mKeyText->setText( getHexString( &binRand ) );
    }

    JS_BIN_reset( &binRand );
}

void KeyAddDlg::changeKeyType()
{
    QString strKey = mKeyText->text();

    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), strKey );
    mKeyLenText->setText( strLen );
}

void KeyAddDlg::changeIVType()
{
    QString strIV = mIVText->text();

    QString strLen = getDataLenString( mIVTypeCombo->currentText(), strIV );
    mIVLenText->setText( strLen );
}

void KeyAddDlg::changeType()
{
    QString strType = mTypeCombo->currentText();
    mKeyLenCombo->clear();
    mRandKeyBtn->setEnabled(true);

    if( strType == "AES" || strType == "ARIA" )
    {
        QStringList sLenList = { "16", "24", "32" };
        mKeyLenCombo->addItems( sLenList );
    }
    else if( strType == "SEED" || strType == "TDES" )
    {
        mKeyLenCombo->addItem( "16" );
    }
    else
    {
        mRandKeyBtn->setEnabled(false);
        mKeyLenCombo->addItem( "Any" );
    }
}
