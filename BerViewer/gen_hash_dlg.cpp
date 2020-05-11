#include "ber_define.h"
#include "gen_hash_dlg.h"
#include "ui_gen_hash_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"

#include <QDialogButtonBox>

static QStringList hashTypes = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
};

GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent)
{
//    ui->setupUi(this);
    setupUi(this);
    pctx_ = NULL;

    mOutputHashCombo->addItems( hashTypes );

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(hashInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(hashUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(hashFinal()));
}

GenHashDlg::~GenHashDlg()
{
//    delete ui;
    if( pctx_ ) JS_PKI_hashFree( &pctx_ );
}

void GenHashDlg::hashInit()
{
    int ret = 0;

    if( pctx_ )
    {
        JS_PKI_hashFree( &pctx_ );
        pctx_ = NULL;
    }

    QString strAlg = mOutputHashCombo->currentText();

    ret = JS_PKI_hashInit( &pctx_, strAlg.toStdString().c_str() );
    if( ret == 0 )
    {
        mOutputText->setPlainText( "Init OK" );
    }
    else
        mOutputText->setPlainText( "Init fail" );
}

void GenHashDlg::hashUpdate()
{
    int ret = 0;

    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        if( mInputStringBtn->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)inputStr.toStdString().c_str(), inputStr.length() );
        else if( mInputHexBtn->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Btn->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( inputStr.toStdString().c_str(), &binSrc );
        }
    }

    ret = JS_PKI_hashUpdate( pctx_, &binSrc );
    if( ret == 0 )
    {
        mOutputText->setPlainText( "Update OK" );
    }
    else
        mOutputText->setPlainText( "Update fail" );

    JS_BIN_reset( &binSrc );
}

void GenHashDlg::hashFinal()
{
    int ret = 0;
    BIN binMD = {0,0};

    ret = JS_PKI_hashFinal( pctx_, &binMD );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMD, &pHex );
        mOutputText->setPlainText( pHex );
        JS_free( pHex );
    }
    else
    {
        mOutputText->setPlainText( "Final fail" );
    }

    JS_PKI_hashFree( &pctx_ );
    pctx_ = NULL;
    JS_BIN_reset( &binMD );
}

void GenHashDlg::accept()
{
    int ret = 0;

    BIN binSrc = {0,0};
    BIN binHash = {0,0};
    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        if( mInputStringBtn->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)inputStr.toStdString().c_str(), inputStr.length() );
        else if( mInputHexBtn->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Btn->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( inputStr.toStdString().c_str(), &binSrc );
        }
    }

    QString strHash = mOutputHashCombo->currentText();

    ret = JS_PKI_genHash( strHash.toStdString().c_str(), &binSrc, &binHash );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binHash, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free(pHex );
    }
    else
    {

    }

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binHash);
}
