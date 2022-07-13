#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "common.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList methodTypes = {
    "Encrypt",
    "Decrypt"
};

static QStringList algList = {
    "AES",
    "ARIA",
    "DES",
    "DES3",
    "SEED"
};

static QStringList modeList = {
  "ECB", "CBC", "CTR", "CFB", "OFB"
};

static QStringList modeAEList = {
    "GCM", "CCM"
};

/*
static QStringList algTypes = {
    "aes-128-cbc",
    "aes-128-ecb",
    "aes-128-ctr",
    "aes-128-cfb",
    "aes-128-ofb",
    "aes-192-cbc",
    "aes-192-ecb",
    "aes-192-ctr",
    "aes-192-cfb",
    "aes-192-ofb",
    "aes-256-cbc",
    "aes-256-ecb",
    "aes-256-ctr",
    "aes-256-cfb",
    "aes-256-ofb",
    "des-cbc",
    "des-ebc",
    "des-ctr",
    "aria-128-cbc",
    "aria-128-ecb",
    "aria-128-ctr",
    "aria-128-cfb",
    "aria-128-ofb",
    "aria-192-cbc",
    "aria-192-ecb",
    "aria-192-ctr",
    "aria-192-cfb",
    "aria-192-ofb",
    "aria-256-cbc",
    "aria-256-ecb",
    "aria-256-ctr",
    "aria-256-cfb",
    "aria-256-ofb",
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
*/

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
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(ivChanged()));
    connect( mAADText, SIGNAL(textChanged(const QString&)), this, SLOT(aadChanged()));
    connect( mTagText, SIGNAL(textChanged(const QString&)), this, SLOT(tagChanged()));

    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mIVTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(ivChanged()));
    connect( mAADTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(aadChanged()));
    connect( mTagTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(tagChanged()));

    clickUseAE();
    mCloseBtn->setFocus();
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
    mOutputTypeCombo->setCurrentIndex(1);

    mMethodCombo->addItems( methodTypes );
    mAlgCombo->addItems( algList );
}

void EncDecDlg::showEvent( QShowEvent *event )
{

}

void EncDecDlg::Run()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binIV = {0,0};
    BIN binKey = {0,0};
    BIN binOut = {0,0};
    BIN binAAD = {0,0};
    BIN binTag = {0,0};

    QString strInput = mInputText->toPlainText();
    mOutputText->clear();

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

    char *pOut = NULL;
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();
    QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

    berApplet->log( QString("SymAlg: %1\n").arg( strSymAlg ));

    if( strSymAlg.isEmpty() || strSymAlg.isNull() )
    {
        berApplet->elog( QString("Sym Alg is invalid\n" ));
        goto end;
    }

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

            if( isCCM(strSymAlg) )
                ret = JS_PKI_encryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_encrytGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );

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

            if( isCCM( strSymAlg ) )
                ret = JS_PKI_decryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_decryptGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
        }
    }
    else
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( strAlg == "SEED" )
                ret = JS_PKI_encryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
            else
                ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
        }
        else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
        {
            if( strAlg == "SEED" )
                ret = JS_PKI_decryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
            else
                ret = JS_PKI_decryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
        }
    }



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

    if( ret == 0 )
    {
        mStatusLabel->setText( "OK" );
    }
    else
        mStatusLabel->setText( "Fail" );

end :
    if( pOut ) JS_free(pOut);
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );

    repaint();
}

void EncDecDlg::clickUseAE()
{
    bool bStatus = mUseAECheck->isChecked();

    mModeCombo->clear();

    if( bStatus )
    {
        mModeCombo->addItems( modeAEList );
    }
    else
    {
        mModeCombo->addItems( modeList );
    }

    mAADText->setEnabled( bStatus );
    mAADTypeCombo->setEnabled( bStatus );
    mTagText->setEnabled( bStatus );
    mTagTypeCombo->setEnabled( bStatus );
    mCCMInitLength->setEnabled( bStatus );

    mPadCheck->setEnabled( !bStatus );
}

void EncDecDlg::encDecInit()
{
    int ret = -1;
    BIN binSrc = {0,0};
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

    mOutputText->clear();

    QString strInput = mInputText->toPlainText();

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

        int nInitLen = mCCMInitLength->text().toInt();
        if( nInitLen <= 0 )
        {
            nInitLen = binSrc.nLen;
            mCCMInitLength->setText( QString("%1").arg( nInitLen ));
        }

        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( isCCM( strAlg) )
                ret = JS_PKI_encryptCCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD, nInitLen );
            else
                ret = JS_PKI_encryptGCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
        }
        else
        {
            if( isCCM( strAlg ) )
                ret = JS_PKI_decryptCCMInit( &ctx_, strAlg.toStdString().c_str(), &binIV, &binKey, &binAAD, nInitLen );
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
    JS_BIN_reset( &binSrc );

    repaint();
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

    repaint();
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

    repaint();
}

void EncDecDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    repaint();
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

void EncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::outputChanged()
{
    int nLen = getDataLen( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::keyChanged()
{
    int nLen = getDataLen( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::ivChanged()
{
    int nLen = getDataLen( mIVTypeCombo->currentText(), mIVText->text() );
    mIVLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::aadChanged()
{
    int nLen = getDataLen( mAADTypeCombo->currentText(), mAADText->text() );
    mAADLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::tagChanged()
{
    int nLen = getDataLen( mTagTypeCombo->currentText(), mTagText->text() );
    mTagLenText->setText( QString("%1").arg(nLen));
}
