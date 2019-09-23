#include "ber_define.h"
#include "gen_hash_dlg.h"
#include "ui_gen_hash_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"

#include <QDialogButtonBox>

static const char *hashTypes[] = {
    "md5",
    "sha1",
    "sha224",
    "sha384",
    "sha512"
};

GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent)
{
//    ui->setupUi(this);
    setupUi(this);

    QStringList typeList;

    for( int i=0; i < (sizeof(hashTypes) / sizeof(hashTypes[0])); i++ )
        typeList.push_back( hashTypes[i] );

    mOutputHashCombo->addItems( typeList );
}

GenHashDlg::~GenHashDlg()
{
//    delete ui;
}

void GenHashDlg::accept()
{
    int ret = 0;
    int hash_sel = 0;
    BIN binSrc = {0,0};
    BIN binHash = {0,0};
    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data" ), this );
        return;
    }

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

    hash_sel = mOutputHashCombo->currentIndex();

    ret = JS_PKI_genHash( hashTypes[hash_sel], &binSrc, &binHash );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binHash, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free(pHex );
    }

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binHash);
}
