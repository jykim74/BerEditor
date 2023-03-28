#include "js_ber.h"
#include "js_pki.h"
#include "js_kw.h"

#include "key_man_dlg.h"
#include "ber_applet.h"
#include "common.h"

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


KeyManDlg::KeyManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(PBKDF()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(keyValueChanged()));

    connect( mPasswordText, SIGNAL(textChanged(const QString&)), this, SLOT(passwordChanged()));
    connect( mSaltText, SIGNAL(textChanged(const QString&)), this, SLOT(saltChanged()));
    connect( mSaltTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(saltChanged()));

    connect( mWrapBtn, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapBtn, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));

    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));
    connect( mDstText, SIGNAL(textChanged()), this, SLOT(dstChanged()));
    connect( mKEKText, SIGNAL(textChanged(const QString&)), this, SLOT(kekChanged(const QString&)));


    initialize();
}

KeyManDlg::~KeyManDlg()
{

}

void KeyManDlg::initialize()
{
    mHashCombo->addItems( hashTypes );
    mSaltTypeCombo->addItems( dataTypes );

    mKeyLenText->setText( "32" );
    mIterCntText->setText( "1024" );
    mCloseBtn->setFocus();

    tabWidget->setCurrentIndex(0);
}

void KeyManDlg::PBKDF()
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
    nIter = mIterCntText->text().toInt();
    nKeySize = mKeyLenText->text().toInt();

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
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );

        berApplet->log( QString( "Passwd : %1").arg( strPasswd ));
        berApplet->log( QString( "Hash   : %1 Iteration Count: %2").arg( strHash ).arg( nIter ));
        berApplet->log( QString( "Salt   : %1" ).arg(getHexString(&binSalt)));
        berApplet->log( QString( "Key    : %1" ).arg(getHexString(&binKey)));
    }

    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binKey );

    repaint();
}

void KeyManDlg::passwordChanged()
{
    int nLen = getDataLen( DATA_STRING, mPasswordText->text() );
    mPasswordLenText->setText(QString("%1").arg(nLen));
}

void KeyManDlg::saltChanged()
{
    int nLen = getDataLen( mSaltTypeCombo->currentText(), mSaltText->text() );
    mSaltLenText->setText( QString("%1").arg(nLen));
}


void KeyManDlg::keyValueChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}


void KeyManDlg::clickWrap()
{
    int ret = 0;
    BIN binInput = {0,0};
    BIN binWrappingKey = {0,0};
    BIN binOutput = {0,0};
    int nMode = 0;

    QString strInput = mSrcText->toPlainText();
    QString strWrappingKey = mKEKText->text();

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( "You have to write input data", this );
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "You have to write wrapping key data", this );
        goto end;
    }

    if( mKWRadio->isChecked() )
        nMode = JS_KW_MODE_KW;
    else
        nMode = JS_KW_MODE_KWP;

    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    JS_BIN_decodeHex( strWrappingKey.toStdString().c_str(), &binWrappingKey );

    ret = JS_KW_WrapKey( nMode, &binInput, &binWrappingKey, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( QString( "fail to wrap key: %1").arg(ret));
        goto end;
    }

    mDstText->setPlainText( getHexString(binOutput.pVal, binOutput.nLen));

    berApplet->log( QString( "Input Key   : %1" ).arg(getHexString(&binInput)));
    berApplet->log( QString( "Wrapping Key: %1" ).arg( getHexString( &binWrappingKey)));
    berApplet->log( QString( "Wrapped Key : %1" ).arg( getHexString(&binOutput)));

end :
    JS_BIN_reset( &binInput );
    JS_BIN_reset( &binWrappingKey );
    JS_BIN_reset( &binOutput );
}

void KeyManDlg::clickUnwrap()
{
    int ret = 0;
    BIN binInput = {0,0};
    BIN binWrappingKey = {0,0};
    BIN binOutput = {0,0};
    int nMode = 0;

    QString strInput = mSrcText->toPlainText();
    QString strWrappingKey = mKEKText->text();

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( "You have to write input data", this );
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "You have to write wrapping key data", this );
        goto end;
    }

    if( mKWRadio->isChecked() )
        nMode = JS_KW_MODE_KW;
    else
        nMode = JS_KW_MODE_KWP;

    JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
    JS_BIN_decodeHex( strWrappingKey.toStdString().c_str(), &binWrappingKey );

    ret = JS_KW_UnwrapKey( nMode, &binInput, &binWrappingKey, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( QString( "fail to unwrap key: %1").arg(ret), this );
        goto end;
    }

    mDstText->setPlainText( getHexString(binOutput.pVal, binOutput.nLen));

    berApplet->log( QString( "Input Key      : %1" ).arg(getHexString(&binInput)));
    berApplet->log( QString( "Unwrapping Key : %1" ).arg( getHexString( &binWrappingKey)));
    berApplet->log( QString( "Unwrapped Key  : %1" ).arg( getHexString(&binOutput)));

end :
    JS_BIN_reset( &binInput );
    JS_BIN_reset( &binWrappingKey );
    JS_BIN_reset( &binOutput );
}

void KeyManDlg::clickClear()
{
    mSrcText->clear();
    mDstText->clear();
    mKEKText->clear();
}

void KeyManDlg::clickChange()
{
    QString strDst = mDstText->toPlainText();
    mSrcText->setPlainText( strDst );
    mDstText->clear();
}

void KeyManDlg::srcChanged()
{
    int nLen = mSrcText->toPlainText().length() / 2;
    mSrcLenText->setText( QString("%1").arg(nLen));
}

void KeyManDlg::dstChanged()
{
    int nLen = mDstText->toPlainText().length() / 2;
    mDstLenText->setText( QString("%1").arg(nLen));
}

void KeyManDlg::kekChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mKEKLenText->setText( QString("%1").arg(nLen));
}
