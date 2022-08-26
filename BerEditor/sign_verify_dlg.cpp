#include <QFileDialog>

#include "sign_verify_dlg.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "js_bin.h"
#include "js_pki.h"
#include "common.h"

static QStringList algTypes = {
    "RSA",
    "ECDSA"
};

static QStringList hashTypes = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3"
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

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mAlgTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(signVerifyInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(signVerifyUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(signVerifyFinal()));

    connect( mPubKeyVerifyCheck, SIGNAL(clicked()), this, SLOT(clickPubKeyVerify()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    mCloseBtn->setFocus();
}

SignVerifyDlg::~SignVerifyDlg()
{
    if( sctx_ ) JS_PKI_signFree( &sctx_ );
}

void SignVerifyDlg::initialize()
{
    mAlgTypeCombo->addItems(algTypes);
    mHashTypeCombo->addItems(hashTypes);
    mVersionCombo->addItems(versionTypes);
    mMethodCombo->addItems(methodTypes);
}

void SignVerifyDlg::clickPubKeyVerify()
{
    bool bVal = mPubKeyVerifyCheck->isChecked();

    if( bVal )
    {
        mCertBtn->setText( tr("Public Key" ) );
        mPriKeyAndCertLabel->setText( tr("Private key and Public key" ));
    }
    else
    {
        mCertBtn->setText( tr("Certificate") );
        mPriKeyAndCertLabel->setText( tr( "Private key and Certificate" ));
    }
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

    JS_BIN_fileRead( strPriPath.toStdString().c_str(), &binPri );

    if( mPubKeyVerifyCheck->isChecked() )
    {
        JS_BIN_fileRead( strCertPath.toStdString().c_str(), &binPub );
    }
    else
    {
        JS_BIN_fileRead( strCertPath.toStdString().c_str(), &binCert );
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
        ret = JS_PKI_IsValidECCKeyPair( &binPri, &binPubVal );
    }

    if( ret == 1 )
        berApplet->messageBox( "KeyPair is good", this );
    else
        berApplet->warningBox( QString( "Invalid key pair: %1").arg(ret));

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubVal );
}

void SignVerifyDlg::findPrivateKey()
{
    QString strPath = berApplet->getSetPath();

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);

    repaint();
}

void SignVerifyDlg::findCert()
{
    QString strPath = berApplet->getSetPath();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText( fileName );

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

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    QString strHash = mHashTypeCombo->currentText();

    if( mAlgTypeCombo->currentIndex() == 0 )
        nType = JS_PKI_KEY_TYPE_RSA;
    else
        nType = JS_PKI_KEY_TYPE_ECC;

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileRead( mPriKeyPath->text().toStdString().c_str(), &binPri );

        ret = JS_PKI_signInit( &sctx_, strHash.toStdString().c_str(), nType, &binPri );
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileRead( mCertPath->text().toStdString().c_str(), &binCert );

        if( mPubKeyVerifyCheck->isChecked() )
            ret = JS_PKI_verifyInit( &sctx_, strHash.toStdString().c_str(), &binCert );
        else
            ret = JS_PKI_verifyInitWithCert( &sctx_, strHash.toStdString().c_str(), &binCert );
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
    }
    else
        mStatusLabel->setText( "Init fail" );

    repaint();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
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
        ret = JS_PKI_signUpdate( sctx_, &binSrc );
    else
        ret = JS_PKI_verifyUpdate( sctx_, &binSrc );

    if( ret == 0 )
    {
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( "Update Fail" );

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

    if( ret == 1 )
    {
        mStatusLabel->setText( "Final OK" );
    }
    else
        mStatusLabel->setText( "Final Fail" );

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

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileRead( mPriKeyPath->text().toStdString().c_str(), &binPri );

        if( mAlgTypeCombo->currentIndex() == 0 )
            JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), nVersion, &binSrc, &binPri, &binOut );
        else {
            JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileRead( mCertPath->text().toStdString().c_str(), &binCert );
        JS_BIN_decodeHex( mOutputText->toPlainText().toStdString().c_str(), &binOut );

        if( mAlgTypeCombo->currentIndex() == 0 )
        {
            if( mPubKeyVerifyCheck->isChecked() )
                ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binCert );
            else
                ret = JS_PKI_RSAVerifySignWithCert( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binCert );
        }
        else {
            if( mPubKeyVerifyCheck->isChecked() )
                ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binSrc, &binOut, &binCert );
            else
                ret = JS_PKI_ECCVerifySignWithCert( strHash.toStdString().c_str(), &binSrc, &binOut, &binCert );
        }

        if( ret == 1 )
            berApplet->messageBox( tr("Verify Success") );
        else {
            berApplet->warningBox( tr("Verify Fail") );
        }
    }

    repaint();
end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binOut );
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
