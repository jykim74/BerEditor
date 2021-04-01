#include "key_derive_dlg.h"
#include "ber_applet.h"
#include "common.h"

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

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mKeyValueText, SIGNAL(textChanged()), this, SLOT(keyValueChanged()));

    connect( mPasswordText, SIGNAL(textChanged(const QString&)), this, SLOT(passwordChanged()));
    connect( mSaltText, SIGNAL(textChanged(const QString&)), this, SLOT(saltChanged()));
    connect( mSaltTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(saltChanged()));

    mHashCombo->addItems( hashTypes );
    mSaltTypeCombo->addItems( dataTypes );

    mKeySizeText->setText( "32" );
    mIterCountText->setText( "1024" );

    mCloseBtn->setFocus();
}

KeyDeriveDlg::~KeyDeriveDlg()
{

}

void KeyDeriveDlg::Run()
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

    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binKey );

    repaint();
}

void KeyDeriveDlg::passwordChanged()
{
    int nLen = getDataLen( DATA_STRING, mPasswordText->text() );
    mPasswordLenText->setText(QString("%1").arg(nLen));
}

void KeyDeriveDlg::saltChanged()
{
    int nLen = getDataLen( mSaltTypeCombo->currentText(), mSaltText->text() );
    mSaltLenText->setText( QString("%1").arg(nLen));
}


void KeyDeriveDlg::keyValueChanged()
{
    int nLen = getDataLen( DATA_HEX, mKeyValueText->toPlainText() );
    mKeyValueLenText->setText( QString("%1").arg(nLen));
}
