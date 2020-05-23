#include "key_derive_dlg.h"
#include "ber_applet.h"

#include "js_pki.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList hashTypes = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
};

KeyDeriveDlg::KeyDeriveDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mHashCombo->addItems( hashTypes );
    mSaltTypeCombo->addItems( dataTypes );

    mKeySizeText->setText( "32" );
    mIterCountText->setText( "1024" );
}

KeyDeriveDlg::~KeyDeriveDlg()
{

}

void KeyDeriveDlg::accept()
{
    int ret = 0;
    BIN binSalt = { 0,0 };
    BIN binKey = { 0, 0 };
    int nIter = 0;
    int nKeySize = 0;

    QString strPasswd = mPasswordText->text();

    if( strPasswd.length() <= 0 )
    {
        berApplet->warningBox( tr( "You have to insert password value"), this );
        return;
    }

    QString strHash = mHashCombo->currentText();
    nIter = mIterCountText->text().toInt();
    nKeySize = mKeySizeText->text().toInt();

    QString strSalt = mSaltText->text();

    if( mSaltTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binSalt, (unsigned char *)strSalt.toStdString().c_str(), strSalt.length() );
    else if( mSaltTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strSalt.toStdString().c_str(), &binSalt );
    else if( mSaltTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strSalt.toStdString().c_str(), &binSalt );


    ret = JS_PKI_PBKDF2( strPasswd.toStdString().c_str(), &binSalt, nIter, strHash.toStdString().c_str(), nKeySize, &binKey );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binKey, &pHex );
        mKeyValueText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );
    }

    mKeyValueText->repaint();
    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binKey );
}
