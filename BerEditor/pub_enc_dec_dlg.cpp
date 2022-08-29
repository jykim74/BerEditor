#include <QFileDialog>

#include "pub_enc_dec_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"

static QStringList algTypes = {
    "RSA",
    "SM2"
};

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};


static QStringList versionTypes = {
    "V15",
    "V21"
};

static QStringList methodTypes = {
    "Encrypt",
    "Decrypt"
};

PubEncDecDlg::PubEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(changeValue()));
    connect( mPubKeyEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubKeyEncrypt()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));

    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outputChanged()));
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged()));

    mCloseBtn->setFocus();
}

PubEncDecDlg::~PubEncDecDlg()
{

}

void PubEncDecDlg::initialize()
{
    mAlgCombo->addItems( algTypes );

    mOutputTypeCombo->addItems(dataTypes);
    mOutputTypeCombo->setCurrentIndex(1);

    mVersionTypeCombo->addItems(versionTypes);
    mMethodTypeCombo->addItems(methodTypes);
}

void PubEncDecDlg::clickPubKeyEncrypt()
{
    bool bVal = mPubKeyEncryptCheck->isChecked();

    if( bVal )
    {
        mCertBtn->setText(tr("Public Key"));
        mPriKeyAndCertLabel->setText( tr("Private key and Public key" ));
    }
    else
    {
        mCertBtn->setText(tr("Certificate"));
        mPriKeyAndCertLabel->setText( tr("Private key and Certificate"));
    }
}

void PubEncDecDlg::clickCheckKeyPair()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binCert = {0,0};
    BIN binPubVal = {0,0};

    QString strPriPath = mPriKeyPath->text();
    QString strCertPath = mCertPath->text();
    QString strAlg = mAlgCombo->currentText();

    if( strPriPath.length() < 1 )
    {
        berApplet->elog( "You have to find private key" );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->elog( "You have to find publick key" );
        return;
    }

    JS_BIN_fileRead( strPriPath.toStdString().c_str(), &binPri );

    if( mPubKeyEncryptCheck->isChecked() )
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

    if( strAlg == "RSA" )
        ret = JS_PKI_IsValidRSAKeyPair( &binPri, &binPubVal );
    else
        ret = JS_PKI_IsValidECCKeyPair( &binPri, &binPub );

    if( ret == 1 )
        berApplet->messageBox( "KeyPair is good", this );
    else
        berApplet->warningBox( QString( "Invalid key pair: %1").arg(ret), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPubVal );
    JS_BIN_reset( &binCert );
}

void PubEncDecDlg::Run()
{
    int ret = 0;
    int nVersion = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binOut = {0,0};
    char *pOut = NULL;

    QString strAlg = mAlgCombo->currentText();
    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
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

    if( mVersionTypeCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    if( mMethodTypeCombo->currentIndex() == ENC_ENCRYPT )
    {     
        if( mCertBtn->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileRead( mCertPath->text().toStdString().c_str(), &binCert );

        if( strAlg == "RSA" )
        {
            if( mPubKeyEncryptCheck->isChecked() )
                JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binCert, &binOut );
            else
                JS_PKI_RSAEncryptWithCert( nVersion, &binSrc, &binCert, &binOut );
        }
        else
        {
            if( mPubKeyEncryptCheck->isChecked() )
                JS_PKI_SM2EncryptWithPub( &binSrc, &binCert, &binOut );
            else
                JS_PKI_SM2EncryptWithCert( &binSrc, &binCert, &binOut );
        }
    }
    else {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileRead( mPriKeyPath->text().toStdString().c_str(), &binPri );

        if( strAlg == "RSA" )
            JS_PKI_RSADecryptWithPri( nVersion, &binSrc, &binPri, &binOut );
        else
            JS_PKI_SM2DecryptWithPri( &binSrc, &binPri, &binOut );
    }

    if( mOutputTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_string( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_encodeHex( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_encodeBase64( &binOut, &pOut );

    mOutputText->setPlainText(pOut);

end :
    repaint();

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binCert);
    JS_BIN_reset(&binOut);
    if( pOut ) JS_free(pOut);
}

void PubEncDecDlg::findCert()
{
    QString strPath = berApplet->getSetPath();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText(fileName);

    repaint();
}

void PubEncDecDlg::findPrivateKey()
{
    QString strPath = berApplet->getSetPath();

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);

    repaint();
}

void PubEncDecDlg::changeValue()
{
//    QString strInput = mInputText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
//    mOutputText->setPlainText( "" );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    repaint();
}

void PubEncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void PubEncDecDlg::outputChanged()
{
    int nLen = getDataLen( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void PubEncDecDlg::algChanged()
{
    QString strAlg = mAlgCombo->currentText();

    if( strAlg == "RSA" )
        mVersionTypeCombo->setEnabled( true );
    else
        mVersionTypeCombo->setEnabled( false );
}
