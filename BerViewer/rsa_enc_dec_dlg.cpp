#include <QFileDialog>

#include "rsa_enc_dec_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_define.h"

static const char *dataTypes[] = {
    "String",
    "Hex",
    "Base64"
};

static const char *algTypes[] = {
    "RSA",
    "ECDSA"
};

static const char *hashTypes[] = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512"
};

static const char *versionTypes[] = {
    "V15",
    "V21"
};

static const char *methodTypes[] = {
    "Encrypt",
    "Decrypt"
};

RSAEncDecDlg::RSAEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mPubKeyBtn, SIGNAL(clicked()), this, SLOT(findPublicKey()));
}

RSAEncDecDlg::~RSAEncDecDlg()
{

}

void RSAEncDecDlg::initialize()
{
    QStringList dataList;

    for( int i=0; i < (sizeof(dataTypes) / sizeof(dataTypes[0])); i++ )
        dataList.push_back( dataTypes[i] );

    mOutputTypeCombo->addItems(dataList);

    QStringList hashList;
    for( int i=0; i < (sizeof(hashTypes) / sizeof(hashTypes[0])); i++ )
        hashList.push_back(hashTypes[i]);
    mHashTypeCombo->addItems(hashList);

    QStringList versionList;
    for( int i=0; i < (sizeof(versionTypes) / sizeof(versionTypes[0])); i++)
        versionList.push_back(versionTypes[i]);
    mVersionTypeCombo->addItems(versionList);

    QStringList methodList;
    for( int i=0; i < (sizeof(methodTypes) / sizeof(methodTypes[0])); i++ )
        methodList.push_back(methodTypes[i] );
    mMethodTypeCombo->addItems(methodList);
}

void RSAEncDecDlg::accept()
{
    int ret = 0;
    int nVersion = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binOut = {0,0};
    char *pOut = NULL;

    QString strInput = mInputText->toPlainText();

    if( mInputStringBtn->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexBtn->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mInputBase64Btn->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    QString strHash = mHashTypeCombo->currentText();

    if( mVersionTypeCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    if( mMethodTypeCombo->currentIndex() == ENC_ENCRYPT )
    {
        JS_BIN_fileRead( mPubKeyPath->text().toStdString().c_str(), &binPub );
        JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binPub, &binOut );
    }
    else {
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

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binPub);
    JS_BIN_reset(&binOut);
    if( pOut ) JS_free(pOut);
}

void RSAEncDecDlg::findPublicKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;DER Files (*.der)"),
                                                     &selectedFilter,
                                                     options );

    mPubKeyPath->setText(fileName);
}

void RSAEncDecDlg::findPrivateKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;DER Files (*.der)"),
                                                     &selectedFilter,
                                                     options );

    mPriKeyPath->setText(fileName);
}
