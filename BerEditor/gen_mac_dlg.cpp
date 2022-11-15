#include <QStringList>
#include <QButtonGroup>

#include "js_ber.h"
#include "gen_mac_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "common.h"

#define JS_TYPE_HMAC    0
#define JS_TYPE_CMAC    1

static QStringList hashTypes = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "SM3"
};

static QStringList cryptList = {
    "AES",
    "ARIA",
    "DES3",
    "SM4"
};

static QStringList modeList = {
  "ECB", "CBC", "CTR", "CFB", "OFB"
};


static QStringList keyTypes = {
    "String",
    "Hex",
    "Base64"
};

GenMacDlg::GenMacDlg(QWidget *parent) :
    QDialog(parent)
{
    hctx_ = NULL;
    type_ = 0;
    group_ = new QButtonGroup;
    setupUi(this);



    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(macInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(macUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(macFinal()));

    connect( mMACBtn, SIGNAL(clicked()), this, SLOT(mac()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(inputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(outputClear()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mHMACRadio, SIGNAL(clicked()), this, SLOT(checkHMAC()));
    connect( mCMACRadio, SIGNAL(clicked()), this, SLOT(checkCMAC()));

    initialize();

    mCloseBtn->setFocus();
}

GenMacDlg::~GenMacDlg()
{
    if( group_ ) delete group_;
    freeCTX();
}

void GenMacDlg::initialize()
{
    mKeyTypeCombo->addItems( keyTypes );
    mModeTypeCombo->addItems( modeList );

    group_->addButton( mHMACRadio );
    group_->addButton( mCMACRadio );

    checkHMAC();
}

void GenMacDlg::freeCTX()
{
    if( hctx_ )
    {
        if( type_ == JS_TYPE_CMAC )
            JS_PKI_cmacFree( &hctx_ );
        else
            JS_PKI_hmacFree( &hctx_ );

        hctx_ = NULL;
    }

    type_ = 0;
}

void GenMacDlg::macInit()
{
    int ret = 0;


    BIN binKey = {0,0};

    QString strKey = mKeyText->text();

    if( mKeyTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );


   QString strAlg = mAlgTypeCombo->currentText();
   QString strMode = mModeTypeCombo->currentText();

   if( mCMACRadio->isChecked() )
   {
        QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

        ret = JS_PKI_cmacInit( &hctx_, strSymAlg.toStdString().c_str(), &binKey );
        if( ret == 0 ) type_ = JS_TYPE_CMAC;
   }
   else
   {
        ret = JS_PKI_hmacInit( &hctx_, strAlg.toStdString().c_str(), &binKey );
        if( ret == 0 ) type_ = JS_TYPE_HMAC;
   }

   if( ret == 0 )
   {
       mStatusLabel->setText( "Init OK" );
   }
   else
       mStatusLabel->setText( "Init fail" );

   JS_BIN_reset( &binKey );
   repaint();
}

void GenMacDlg::macUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
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
    }

    if( mCMACRadio->isChecked() )
    {
        if( type_ == JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_cmacUpdate( hctx_, &binSrc );
    }
    else
    {
        if( type_ == JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_hmacUpdate( hctx_, &binSrc );
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( "Updata fail" );

    JS_BIN_reset( &binSrc );
    repaint();
}

void GenMacDlg::macFinal()
{
    int ret = 0;
    BIN binMAC = {0,0};

    if( mCMACRadio->isChecked() )
    {
        if( type_ == JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_cmacFinal( hctx_, &binMAC );
    }
    else
    {
        if( type_ == JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_hmacFinal( hctx_, &binMAC );
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMAC, &pHex );
        mOutputText->setPlainText( pHex );
        mStatusLabel->setText( "Final OK" );
        JS_free( pHex );
    }
    else
        mStatusLabel->setText( "Final fail" );

    freeCTX();

    JS_BIN_reset( &binMAC );

    repaint();
}

void GenMacDlg::mac()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binMAC = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
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
    }

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert key"), this );
        JS_BIN_reset(&binSrc);
        return;
    }

    if( mKeyTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );


   QString strAlg = mAlgTypeCombo->currentText();
   QString strMode = mModeTypeCombo->currentText();

   if( mCMACRadio->isChecked() )
   {
       QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );
       ret = JS_PKI_genCMAC( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
   }
   else
   {
        ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
   }

   if( ret == 0 )
   {
       char *pHex = NULL;
       JS_BIN_encodeHex( &binMAC, &pHex );
       mOutputText->setPlainText( pHex );
       mStatusLabel->setText( "MAC OK" );
       if( pHex ) JS_free(pHex);
   }
   else
   {
       mStatusLabel->setText( "MAC FAIL" );
   }

   JS_BIN_reset(&binSrc);
   JS_BIN_reset(&binKey);
   JS_BIN_reset(&binMAC);

   repaint();
}

void GenMacDlg::inputClear()
{
    mInputText->clear();
    repaint();
}

void GenMacDlg::outputClear()
{
    mOutputText->clear();
    repaint();
}

void GenMacDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::outputChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::keyChanged()
{
    int nLen = getDataLen( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::checkHMAC()
{
    mHMACRadio->setChecked(true);
    mModeTypeCombo->setDisabled(true);

    mAlgTypeCombo->clear();
    mAlgTypeCombo->addItems( hashTypes );
}

void GenMacDlg::checkCMAC()
{
    mCMACRadio->setChecked(true);
    mModeTypeCombo->setDisabled(false);

    mAlgTypeCombo->clear();
    mAlgTypeCombo->addItems( cryptList );
}
