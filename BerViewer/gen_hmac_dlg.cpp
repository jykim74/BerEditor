#include "ber_define.h"
#include "gen_hmac_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"

static const char *hashTypes[] = {
    "md5",
    "sha1",
    "sha224",
    "sha384",
    "sha512"
};

static const char *keyTypes[] = {
    "String",
    "Hex",
    "Base64"
};

GenHmacDlg::GenHmacDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    QStringList algList;

    for( int i=0; i < (sizeof(hashTypes) / sizeof(hashTypes[0])); i++ )
        algList.push_back( hashTypes[i] );

    mAlgTypeCombo->addItems( algList );

    QStringList typeList;

    for( int i=0; i < (sizeof(keyTypes) / sizeof(keyTypes[0])); i++ )
        typeList.push_back( keyTypes[i] );

    mKeyTypeCombo->addItems(typeList);
}

GenHmacDlg::~GenHmacDlg()
{

}

void GenHmacDlg::accept()
{
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHmac = {0,0};

    QString strInput = mInputText->toPlainText();

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

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data" ), this );
        return;
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
       if( pHex ) JS_free(pHex);
   }


   JS_BIN_reset(&binSrc);
   JS_BIN_reset(&binKey);
   JS_BIN_reset(&binHmac);
}
