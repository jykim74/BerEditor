#include <QFileDialog>

#include "sign_verify_dlg.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "cert_info_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "common.h"

static QStringList algTypes = {
    "RSA",
    "ECDSA",
    "SM2"
};

static QStringList versionTypes = {
    "V15",
    "V21"
};

static QStringList methodTypes = {
    "Signature",
    "Verify"
};

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    sctx_ = NULL;
    setupUi(this);
    initialize();

    last_path_ = berApplet->getSetPath();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mAlgTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));
    connect( mMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMethod(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(signVerifyInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(signVerifyUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(signVerifyFinal()));

    connect( mAutoCertPubKeyCheck, SIGNAL(clicked()), this, SLOT(checkAutoCertOrPubKey()));
    connect( mPubKeyVerifyCheck, SIGNAL(clicked()), this, SLOT(checkPubKeyVerify()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

    connect( mUseKeyAlgCheck, SIGNAL(clicked()), this, SLOT(checkUseKeyAlg()));

    mCloseBtn->setFocus();
}

SignVerifyDlg::~SignVerifyDlg()
{
    if( sctx_ ) JS_PKI_signFree( &sctx_ );
}

void SignVerifyDlg::initialize()
{
    mAlgTypeCombo->addItems(algTypes);
    mHashTypeCombo->addItems(kHashList);
    mHashTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mVersionCombo->addItems(versionTypes);
    mMethodCombo->addItems(methodTypes);

    checkUseKeyAlg();
}

void SignVerifyDlg::checkPubKeyVerify()
{
    bool bVal = mPubKeyVerifyCheck->isChecked();

    if( bVal )
    {
        mCertBtn->setText( tr("Public Key" ) );
        mPriKeyAndCertLabel->setText( tr("Private key and Public key" ));
        mCertViewBtn->setEnabled(false);
    }
    else
    {
        mCertBtn->setText( tr("Certificate") );
        mPriKeyAndCertLabel->setText( tr( "Private key and Certificate" ));
        mCertViewBtn->setEnabled(true);
    }
}

void SignVerifyDlg::checkAutoCertOrPubKey()
{
    bool bVal = mAutoCertPubKeyCheck->isChecked();

    mPubKeyVerifyCheck->setEnabled( !bVal );
}

void SignVerifyDlg::clickCheckKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binCert = {0,0};
    BIN binPubVal = {0,0};

    QString strPriPath = mPriKeyPath->text();
    QString strCertPath = mCertPath->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->elog( "You have to find private key" );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->elog( "You have to find cert" );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( mUseKeyAlgCheck->isChecked() )
    {
        int nAlgType = JS_PKI_getPriKeyType( &binPri );

        if( nAlgType == JS_PKI_KEY_TYPE_RSA )
            mAlgTypeCombo->setCurrentText( "RSA" );
        else if( nAlgType == JS_PKI_KEY_TYPE_ECC )
            mAlgTypeCombo->setCurrentText( "ECDSA" );
        else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
            mAlgTypeCombo->setCurrentText( "SM2" );
    }

    if( mAutoCertPubKeyCheck->isChecked() )
    {
        if( JS_PKI_isCert( &binCert ) == 0 )
            mPubKeyVerifyCheck->setChecked( true );
        else
            mPubKeyVerifyCheck->setChecked( false );
    }

    if( mPubKeyVerifyCheck->isChecked() )
    {
        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binPub );
    }
    else
    {
        ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
        if( ret != 0 ) goto end;
    }

    ret = JS_PKI_getPublicKeyValue( &binPub, &binPubVal );
    if( ret != 0 ) goto end;

    if( mAlgTypeCombo->currentText() == "RSA" )
    {
        ret = JS_PKI_IsValidRSAKeyPair( &binPri, &binPubVal );
    }
    else
    {
        ret = JS_PKI_IsValidECCKeyPair( &binPri, &binPub );
    }

    if( ret == 1 )
        berApplet->messageBox( tr("KeyPair is good"), this );
    else
        berApplet->warningBox( QString( tr("Invalid key pair: %1").arg(ret)), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubVal );
}

void SignVerifyDlg::findPrivateKey()
{
    QString strPath = mPriKeyPath->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);
    last_path_ = fileName;

    repaint();
}

void SignVerifyDlg::findCert()
{
    QString strPath = mCertPath->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText( fileName );
    last_path_ = fileName;

    repaint();
}

void SignVerifyDlg::algChanged(int index)
{
    if( index == 0 )
        mVersionCombo->setEnabled(true);
    else
        mVersionCombo->setEnabled(false);
}

void SignVerifyDlg::signVerifyInit()
{
    int ret = 0;
    int nType = 0;
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    QString strHash = mHashTypeCombo->currentText();

    if( mAlgTypeCombo->currentText() == "RSA" )
        nType = JS_PKI_KEY_TYPE_RSA;
    else if( mAlgTypeCombo->currentText() == "SM2" )
        nType = JS_PKI_KEY_TYPE_SM2;
    else
        nType = JS_PKI_KEY_TYPE_ECC;

    berApplet->log( QString( "Algorithm : %1 Hash : %2" ).arg( mAlgTypeCombo->currentText() ).arg( strHash ));

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileReadBER( mPriKeyPath->text().toLocal8Bit().toStdString().c_str(), &binPri );

        if( mUseKeyAlgCheck->isChecked() )
        {
            nType = JS_PKI_getPriKeyType( &binPri );

            if( nType == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( nType == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
            else if( nType == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
        }

        ret = JS_PKI_signInit( &sctx_, strHash.toStdString().c_str(), nType, &binPri );

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Init Private Key : %1" ).arg( getHexString( &binPri )));
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );

        if( mAutoCertPubKeyCheck->isChecked() )
        {
            if( JS_PKI_isCert( &binCert ) == 0 )
            {
                mPubKeyVerifyCheck->setChecked(true);
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            }
            else
            {
                mPubKeyVerifyCheck->setChecked(false);
                JS_BIN_copy( &binPubKey, &binCert );
            }
        }
        else
        {
            if( mPubKeyVerifyCheck->isChecked() == false )
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            else
                JS_BIN_copy( &binPubKey, &binCert );
        }

        if( mUseKeyAlgCheck->isChecked() )
        {
            nType = JS_PKI_getPubKeyType( &binPubKey );
            if( nType == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( nType == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
            else if( nType == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
        }

        ret = JS_PKI_verifyInit( &sctx_, strHash.toStdString().c_str(), &binPubKey );

        berApplet->log( QString( "Algorithm       : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Init Public Key : %1" ).arg(getHexString(&binPubKey)));
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
    }
    else
        mStatusLabel->setText( QString("Init fail:%1").arg(ret) );

    repaint();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SignVerifyDlg::signVerifyUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
    }

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexRadio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    }
    else if( mInputBase64Radio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
    }

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        ret = JS_PKI_signUpdate( sctx_, &binSrc );
        berApplet->log( QString("Update Src : %1").arg( getHexString(&binSrc)));
    }
    else
    {
        ret = JS_PKI_verifyUpdate( sctx_, &binSrc );
        berApplet->log( QString("Update Src : %1").arg( getHexString(&binSrc)));
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( QString("Update Fail:%1").arg( ret) );

    repaint();
    JS_BIN_reset( &binSrc );
}

void SignVerifyDlg::signVerifyFinal()
{
    int ret = 0;
    BIN binSign = {0,0};

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        ret = JS_PKI_signFinal( sctx_, &binSign );
        if( ret == 0 )
        {
            char *pHex = NULL;
            JS_BIN_encodeHex( &binSign, &pHex );
            mOutputText->setPlainText( pHex );
            JS_free( pHex );
        }

        berApplet->log( QString( "Final Signature : %1" ).arg( getHexString(&binSign)));
    }
    else
    {
        QString strOut = mOutputText->toPlainText();
        JS_BIN_decodeHex( strOut.toStdString().c_str(), &binSign );

        ret = JS_PKI_verifyFinal( sctx_, &binSign );
        if( ret == 1 )
            berApplet->messageBox( tr("Verify Success") );
        else {
            berApplet->warningBox( tr("Verify Fail") );
        }
    }

    if( ret == JS_VERIFY )
    {
        mStatusLabel->setText( "Final OK" );
    }
    else
        mStatusLabel->setText( QString("Final Fail:%1").arg(ret) );

    JS_BIN_reset( &binSign );
    JS_PKI_signFree( &sctx_ );

    repaint();
}

void SignVerifyDlg::Run()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
    }

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexRadio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    }
    else if( mInputBase64Radio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
    }

    if( mVersionCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    QString strHash = mHashTypeCombo->currentText();

    berApplet->log( QString( "Algorithm : %1 Hash %2").arg( mAlgTypeCombo->currentText()).arg( strHash ));

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileReadBER( mPriKeyPath->text().toLocal8Bit().toStdString().c_str(), &binPri );

        if( mUseKeyAlgCheck->isChecked() )
        {
            int nAlgType = JS_PKI_getPriKeyType( &binPri );

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
        }

        if( mAlgTypeCombo->currentIndex() == 0 )
            ret = JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), nVersion, &binSrc, &binPri, &binOut );
        else {
            ret = JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Sign Src         : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
        berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));

        if( ret == 0 )
            mStatusLabel->setText( "Sign OK" );
        else
            mStatusLabel->setText( QString("Sign Fail:%1").arg(ret));
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
        JS_BIN_decodeHex( mOutputText->toPlainText().toStdString().c_str(), &binOut );

        if( mAutoCertPubKeyCheck->isChecked() )
        {
            if( JS_PKI_isCert( &binCert ) == 0 )
            {
                mPubKeyVerifyCheck->setChecked(true);
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            }
            else
            {
                mPubKeyVerifyCheck->setChecked(false);
                JS_BIN_copy( &binPubKey, &binCert );
            }
        }
        else
        {
            if( mPubKeyVerifyCheck->isChecked() == false )
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            else
                JS_BIN_copy( &binPubKey, &binCert );
        }

        if( mUseKeyAlgCheck->isChecked() )
        {
            int id = JS_PKI_getPubKeyType( &binPubKey );
            if( id == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( id == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
            else if( id == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
        }

        if( mAlgTypeCombo->currentText() == "RSA" )
        {
            ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binPubKey );
        }
        else {
            ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binSrc, &binOut, &binPubKey );
        }

        berApplet->log( QString( "Algorithm         : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Verify Src        : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Verify Public Key : %1" ).arg(getHexString( &binPubKey )));

        if( ret == JS_VERIFY )
        {
            mStatusLabel->setText( "Verify OK" );
        }
        else
            mStatusLabel->setText( QString("Verify Fail:%1").arg(ret) );

        if( ret == JS_VERIFY )
            berApplet->messageBox( tr("Verify Success"), this );
        else {
            berApplet->warningBox( tr("Verify Fail"), this );
        }
    }

    repaint();
end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPubKey );

    if( pOut ) JS_free( pOut );
}

void SignVerifyDlg::inputChanged()
{
    int nType = DATA_STRING;
    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void SignVerifyDlg::outputChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void SignVerifyDlg::changeMethod( int index )
{
    if( index == 0 )
        mRunBtn->setText( tr( "Sign" ));
    else
        mRunBtn->setText( tr( "Verify"));
}

void SignVerifyDlg::clickPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mPriKeyPath->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SignVerifyDlg::clickCertView()
{
    QString strPath = mCertPath->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SignVerifyDlg::clickCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mCertPath->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SignVerifyDlg::checkUseKeyAlg()
{
    bool bVal = mUseKeyAlgCheck->isChecked();

    mAlgTypeCombo->setEnabled( !bVal );
}
