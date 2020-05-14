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
    "des-ebc",
    "aria-128-cbc",
    "aria-128-ecb",
    "aria-192-cbc",
    "aria-192-ecb",
    "aria-256-cbc",
    "aria-256-ecb"
};

static QStringList algAETypes = {
    "aes-128-ccm",
    "aes-256-ccm",
    "aes-128-gcm",
    "aes-256-gcm",
    "aria-128-ccm",
    "aria-256-ccm",
    "aria-128-gcm",
    "aria-256-gcm"
};

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    ctx_ = NULL;
    setupUi(this);
    initialize();

    connect( mUseAECheck, SIGNAL(clicked()), this, SLOT(clickUseAE()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(encDecInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(encDecUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(encDecFinal()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(dataChange()));

    clickUseAE();
}

EncDecDlg::~EncDecDlg()
{
    if( ctx_ ) JS_PKI_encryptFree( &ctx_ );
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
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
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

            if( isCCM(strAlg) )
                ret = JS_PKI_encryptCCM( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_encrytGCM( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );

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

            if( isCCM( strAlg ) )
                ret = JS_PKI_decryptCCM( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_decryptGCM( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
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

    mPadCheck->setEnabled( !bStatus );
}

void EncDecDlg::encDecInit()
{
    int ret = -1;
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binAAD = {0,0};

    if( ctx_ )
    {
        JS_PKI_encryptFree( &ctx_ );
        ctx_ = NULL;
    }

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert key" ), this );
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
            if( isCCM( strAlg) )
                ret = JS_PKI_encryptCCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
            else
                ret = JS_PKI_encryptGCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
        }
        else
        {
            if( isCCM( strAlg ) )
                ret = JS_PKI_decryptCCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
            else
                ret = JS_PKI_decryptGCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
        }
    }
    else {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            ret = JS_PKI_encryptInit( &ctx_, strAlg.toStdString().c_str(), bPad, &binIV, &binKey );
        }
        else
        {
            ret = JS_PKI_decryptInit( &ctx_, strAlg.toStdString().c_str(), bPad, &binIV, &binKey );
        }
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
        mOutputText->clear();
    }
    else
        mStatusLabel->setText( "Init Fail" );

    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
}

void EncDecDlg::encDecUpdate()
{
    int ret = -1;
    BIN binSrc = {0,0};
    BIN binDst = {0,0};
    BIN binOut = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
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

    QString strOut = mOutputText->toPlainText();

    if( strOut.length() > 0 )
    {
        if( mOutputTypeCombo->currentIndex() == DATA_STRING )
            JS_BIN_set( &binOut, (unsigned char *)strOut.toStdString().c_str(), strOut.length() );
        else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
            JS_BIN_decodeHex( strOut.toStdString().c_str(), &binOut );
        else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
            JS_BIN_decodeBase64( strOut.toStdString().c_str(), &binOut );
    }

    QString strAlg = mAlgCombo->currentText();

    if( mUseAECheck->isChecked() )
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( isCCM(strAlg) )
                ret = JS_PKI_encryptCCMUpdate( ctx_, &binSrc, &binDst );
            else
                ret = JS_PKI_encryptGCMUpdate( ctx_, &binSrc, &binDst );
        }
        else
        {
            if( isCCM(strAlg))
                ret = JS_PKI_decryptCCMUpdate( ctx_, &binSrc, &binDst );
            else
                ret = JS_PKI_decryptGCMUpdate( ctx_, &binSrc, &binDst );
        }
    }
    else {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            ret = JS_PKI_encryptUpdate( ctx_, &binSrc, &binDst );
        }
        else
        {
            ret = JS_PKI_decryptUpdate( ctx_, &binSrc, &binDst );
        }
    }

    if( ret == 0 )
    {
        JS_BIN_appendBin( &binOut, &binDst );
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

        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( "Update Fail" );

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binOut );
}

void EncDecDlg::encDecFinal()
{
    int ret = -1;
    BIN binOut = {0,0};
    BIN binDst = {0,0};
    BIN binTag = {0,0};

    QString strOut = mOutputText->toPlainText();

    if( strOut.length() > 0 )
    {
        if( mOutputTypeCombo->currentIndex() == DATA_STRING )
            JS_BIN_set( &binOut, (unsigned char *)strOut.toStdString().c_str(), strOut.length() );
        else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
            JS_BIN_decodeHex( strOut.toStdString().c_str(), &binOut );
        else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
            JS_BIN_decodeBase64( strOut.toStdString().c_str(), &binOut );
    }

    QString strAlg = mAlgCombo->currentText();

    if( mUseAECheck->isChecked() )
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( isCCM(strAlg) )
                ret = JS_PKI_encryptCCMFinal( ctx_, &binDst, &binTag );
            else
                ret = JS_PKI_encryptGCMFinal( ctx_, &binDst, &binTag );

            if( binTag.nLen > 0 )
            {
                char *pTag = NULL;
                JS_BIN_encodeHex( &binTag, &pTag );
                if( pTag )
                {
                    mTagText->setText( pTag );
                    JS_free( pTag );
                }
            }
        }
        else
        {
            QString strTag = mTagText->text();

            if( mTagTypeCombo->currentIndex() == DATA_STRING )
                JS_BIN_set( &binTag, (unsigned char *)strTag.toStdString().c_str(), strTag.length() );
            else if( mTagTypeCombo->currentIndex() == DATA_HEX )
                JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );
            else if( mTagTypeCombo->currentIndex() == DATA_BASE64 )
                JS_BIN_decodeBase64( strTag.toStdString().c_str(), &binTag );

            if( isCCM(strAlg) )
                ret = JS_PKI_decryptCCMFinal( ctx_, &binTag, &binDst );
            else
                ret = JS_PKI_decryptGCMFinal( ctx_, &binTag, &binDst );
        }
    }
    else {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            ret = JS_PKI_encryptFinal( ctx_, &binDst );
            JS_PKI_encryptFree( &ctx_ );
        }
        else
        {
            ret = JS_PKI_decryptFinal( ctx_, &binDst );
            JS_PKI_decryptFree( &ctx_ );
        }
    }

    if( binDst.nLen > 0 )
    {
        JS_BIN_appendBin( &binOut, &binDst );
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
    }

    if( ret == 0 )
        mStatusLabel->setText( "Final OK" );
    else
        mStatusLabel->setText( "Final Fail" );

    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binTag );
}

void EncDecDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Btn->setChecked(true);
}

bool EncDecDlg::isCCM( const QString strAlg )
{
    QStringList strList = strAlg.split( "-" );

    if( strList.size() < 3 ) return false;

    QString strMode = strList.at(2);

    if( strMode == "ccm" || strMode == "CCM" )
        return true;

    return false;
}
