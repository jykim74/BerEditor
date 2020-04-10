#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"
#include "ber_define.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList methodTypes = {
    "Encrypt",
    "Decrypt"
};

static QStringList algTypes = {
    "aes-128-cbc",
    "aes-128-ecb",
    "aes-192-cbc",
    "aes-192-ecb",
    "aes-256-cbc",
    "aes-256-ecb",
    "des-cbc",
    "des-ebc"
};

static QStringList algAETypes = {
    "aes-256-ccm",
    "aes-256-gcm"
};

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mUseAECheck, SIGNAL(clicked()), this, SLOT(clickUseAE()));
    clickUseAE();
}

EncDecDlg::~EncDecDlg()
{

}

void EncDecDlg::initialize()
{
    mIVTypeCombo->addItems( dataTypes );
    mKeyTypeCombo->addItems( dataTypes );
    mAADTypeCombo->addItems( dataTypes );
    mTagTypeCombo->addItems( dataTypes );
    mOutputTypeCombo->addItems( dataTypes );

    mMethodCombo->addItems( methodTypes );
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
    BIN binAAD = {0,0};
    BIN binTag = {0,0};

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

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert key" ), this );
        JS_BIN_reset(&binSrc);
        return;
    }

    if( mKeyTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );

    QString strIV = mIVText->text();

    if( mIVTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_set( &binIV, (unsigned char *)strIV.toStdString().c_str(), strIV.length() );
    else if( mIVTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
    else if( mIVTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_decodeBase64( strIV.toStdString().c_str(), &binIV );

    bool bPad = mPadCheck->isChecked();

    QString strAlg = mAlgCombo->currentText();

    if( mUseAECheck->isChecked() )
    {
        QString strAAD = mAADText->text();

        if( mAADTypeCombo->currentIndex() == DATA_STRING )
            JS_BIN_set( &binAAD, (unsigned char *)strAAD.toStdString().c_str(), strAAD.length() );
        else if( mAADTypeCombo->currentIndex() == DATA_HEX )
            JS_BIN_decodeHex( strAAD.toStdString().c_str(), &binAAD );
        else if( mAADTypeCombo->currentIndex() == DATA_BASE64 )
            JS_BIN_decodeBase64( strAAD.toStdString().c_str(), &binAAD );

        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            char *pTag = NULL;

            if( strAlg == "aes-256-ccm" )
                ret = JS_PKI_encryptCCM( strAlg.toStdString().c_str(), bPad, &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_encrytGCM( strAlg.toStdString().c_str(), bPad, &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );

            mTagTypeCombo->setCurrentIndex( DATA_HEX );
            JS_BIN_encodeHex( &binTag, &pTag );
            if( pTag )
            {
                mTagText->setText( pTag );
                JS_free( pTag );
            }
        }
        else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
        {
            QString strTag = mTagText->text();

            if( mTagTypeCombo->currentIndex() == DATA_STRING )
                JS_BIN_set( &binTag, (unsigned char *)strTag.toStdString().c_str(), strTag.length() );
            else if( mTagTypeCombo->currentIndex() == DATA_HEX )
                JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );
            else if( mTagTypeCombo->currentIndex() == DATA_BASE64 )
                JS_BIN_decodeBase64( strTag.toStdString().c_str(), &binTag );

            if( strAlg == "aes-256-ccm" )
                ret = JS_PKI_decryptCCM( strAlg.toStdString().c_str(), bPad, &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else if( strAlg == "aes-256-gcm" )
                ret = JS_PKI_decryptGCM( strAlg.toStdString().c_str(), bPad, &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
        }
    }
    else
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
            ret = JS_PKI_encryptData( strAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
        else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
            ret = JS_PKI_decryptData( strAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
    }

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
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );
}

void EncDecDlg::clickUseAE()
{
    bool bStatus = mUseAECheck->isChecked();

    mAlgCombo->clear();

    if( bStatus )
    {
        mAlgCombo->addItems( algAETypes );
    }
    else
    {
        mAlgCombo->addItems( algTypes );
    }

    mAADText->setEnabled( bStatus );
    mAADTypeCombo->setEnabled( bStatus );
    mTagText->setEnabled( bStatus );
    mTagTypeCombo->setEnabled( bStatus );
}
