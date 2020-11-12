#include <QFileDialog>

#include "rsa_enc_dec_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_define.h"
#include "ber_applet.h"

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

RSAEncDecDlg::RSAEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(changeValue()));
    connect( mPubKeyEncryptCheck, SIGNAL(clicked()), this, SLOT(clickPubKeyEncryt()));
}

RSAEncDecDlg::~RSAEncDecDlg()
{

}

void RSAEncDecDlg::initialize()
{
    mOutputTypeCombo->addItems(dataTypes);
    mOutputTypeCombo->setCurrentIndex(1);

    mVersionTypeCombo->addItems(versionTypes);
    mMethodTypeCombo->addItems(methodTypes);
}

void RSAEncDecDlg::clickPubKeyEncryt()
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
void RSAEncDecDlg::accept()
{
    int ret = 0;
    int nVersion = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binOut = {0,0};
    char *pOut = NULL;

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
    }

    if( mInputStringBtn->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexBtn->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    }
    else if( mInputBase64Btn->isChecked() )
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

        if( mPubKeyEncryptCheck->isChecked() )
            JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binCert, &binOut );
        else
            JS_PKI_RSAEncryptWithCert( nVersion, &binSrc, &binCert, &binOut );
    }
    else {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileRead( mPriKeyPath->text().toStdString().c_str(), &binPri );
        JS_PKI_RSADecryptWithPri( nVersion, &binSrc, &binPri, &binOut );
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

void RSAEncDecDlg::findCert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath = QDir::currentPath();

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Certificate File"),
                                                     strPath,
                                                     tr("Certificate Files (*.crt *.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mCertPath->setText(fileName);

    repaint();
}

void RSAEncDecDlg::findPrivateKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath = QDir::currentPath();

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Private Key File"),
                                                     strPath,
                                                     tr("Key Files (*.key *.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mPriKeyPath->setText(fileName);

    repaint();
}

void RSAEncDecDlg::changeValue()
{
//    QString strInput = mInputText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
//    mOutputText->setPlainText( "" );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Btn->setChecked(true);

    repaint();
}
