#include <QStringList>

#include "ber_define.h"
#include "gen_hmac_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"

static QStringList hashTypes = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
};

static QStringList keyTypes = {
    "String",
    "Hex",
    "Base64"
};

GenHmacDlg::GenHmacDlg(QWidget *parent) :
    QDialog(parent)
{
    hctx_ = NULL;
    setupUi(this);

    mAlgTypeCombo->addItems( hashTypes );
    mKeyTypeCombo->addItems( keyTypes );

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(hmacInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(hmacUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(hmacFinal()));

    connect( mHMACBtn, SIGNAL(clicked()), this, SLOT(hmac()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(inputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(outputClear()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

GenHmacDlg::~GenHmacDlg()
{
    if( hctx_ ) JS_PKI_hmacFree( &hctx_ );
}

void GenHmacDlg::hmacInit()
{
    int ret = 0;
    if( hctx_ )
    {
        JS_PKI_hmacFree( &hctx_ );
        hctx_ = NULL;
    }

    BIN binKey = {0,0};

    QString strKey = mKeyText->text();

    if( mKeyTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );


   QString strAlg = mAlgTypeCombo->currentText();

   ret = JS_PKI_hmacInit( &hctx_, strAlg.toStdString().c_str(), &binKey );
   if( ret == 0 )
   {
       mStatusLabel->setText( "Init OK" );
   }
   else
       mStatusLabel->setText( "Init fail" );

   JS_BIN_reset( &binKey );
   repaint();
}

void GenHmacDlg::hmacUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
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
    }

    ret = JS_PKI_hmacUpdate( hctx_, &binSrc );
    if( ret == 0 )
    {
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( "Updata fail" );

    JS_BIN_reset( &binSrc );
    repaint();
}

void GenHmacDlg::hmacFinal()
{
    int ret = 0;
    BIN binHMAC = {0,0};

    ret = JS_PKI_hmacFinal( hctx_, &binHMAC );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binHMAC, &pHex );
        mOutputText->setPlainText( pHex );
        mStatusLabel->setText( "Final OK" );
        JS_free( pHex );
    }
    else
        mStatusLabel->setText( "Final fail" );

    if( hctx_ ) JS_PKI_hmacFree( &hctx_ );
    JS_BIN_reset( &binHMAC );

    repaint();
}

void GenHmacDlg::hmac()
{
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHmac = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
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
   int ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binHmac );
   if( ret == 0 )
   {
       char *pHex = NULL;
       JS_BIN_encodeHex( &binHmac, &pHex );
       mOutputText->setPlainText( pHex );
       mStatusLabel->setText( "HMAC OK" );
       if( pHex ) JS_free(pHex);
   }
   else
   {
       mStatusLabel->setText( "HMAC FAIL" );
   }

   JS_BIN_reset(&binSrc);
   JS_BIN_reset(&binKey);
   JS_BIN_reset(&binHmac);

   repaint();
}

void GenHmacDlg::inputClear()
{
    mInputText->clear();
    repaint();
}

void GenHmacDlg::outputClear()
{
    mOutputText->clear();
    repaint();
}
