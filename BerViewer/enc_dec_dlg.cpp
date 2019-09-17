#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"
#include "ber_define.h"
#include "js_bin.h"
#include "js_pki.h"

static const char *dataTypes[] = {
    "String",
    "Hex",
    "Base64"
};

static const char *methodTypes[] = {
    "Encrypt",
    "Decrypt"
};

static const char *algTypes[] = {
    "aes-128-cbc",
    "aes-128-ecb",
    "aes-192-cbc",
    "aes-192-ecb",
    "aes-256-cbc",
    "aes-256-ecb",
    "des-cbc",
    "des-ebc",
    "des-ede3-cbc",
    "des-ede3-ecb"
};

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();
}

EncDecDlg::~EncDecDlg()
{

}

void EncDecDlg::initialize()
{
    QStringList dataList;

    for( int i=0; i < (sizeof(dataTypes) / sizeof(dataTypes[0])); i++ )
        dataList.push_back( dataTypes[i] );

    mIVTypeCombo->addItems(dataList);
    mKeyTypeCombo->addItems(dataList);
    mOutputTypeCombo->addItems(dataList);

    QStringList methodList;
    for( int i=0; i < (sizeof(methodTypes) / sizeof(methodTypes[0])); i++ )
        methodList.push_back(methodTypes[i]);

    mMethodCombo->addItems(methodList);

    QStringList algList;
    for( int i=0; i < (sizeof(algTypes)/sizeof(algTypes[0])); i++ )
        algList.push_back(algTypes[i]);

    mAlgCombo->addItems(algList);
}

void EncDecDlg::showEvent( QShowEvent *event )
{

}

void EncDecDlg::accept()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binIV = {0,0};
    BIN binKey = {0,0};
    BIN binOut = {0,0};

    QString strInput = mInputText->toPlainText();

    if( mInputStringBtn->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexBtn->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mInputBase64Btn->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    QString strKey = mKeyText->text();

    if( mKeyTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );

    QString strAlg = mAlgCombo->currentText();

    if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        ret = JS_PKI_encryptData( strAlg.toStdString().c_str(), &binSrc, &binIV, &binKey, &binOut );
    else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
        ret = JS_PKI_decryptData( strAlg.toStdString().c_str(), &binSrc, &binIV, &binKey, &binOut );

    char *pOut = NULL;

    if( mOutputTypeCombo->currentIndex() == DATA_STRING )
    {
        JS_BIN_string( &binOut, &pOut );
    }
    else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
    {
        JS_BIN_encodeHex( &binOut, &pOut );
    }
    else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
    {
        JS_BIN_encodeBase64( &binOut, &pOut );
    }

    mOutputText->setPlainText( pOut );

    if( pOut ) JS_free(pOut);
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
}
