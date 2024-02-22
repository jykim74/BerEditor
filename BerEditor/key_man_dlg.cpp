#include "js_ber.h"
#include "js_pki.h"


#include "key_man_dlg.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};


KeyManDlg::KeyManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mMakeKeyBtn, SIGNAL(clicked()), this, SLOT(PBKDF()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(keyValueChanged()));

    connect( mPasswordText, SIGNAL(textChanged(const QString&)), this, SLOT(passwordChanged()));
    connect( mSaltText, SIGNAL(textChanged(const QString&)), this, SLOT(saltChanged()));
    connect( mSaltTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(saltChanged()));

    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    connect( mWrapBtn, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapBtn, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));

    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));
    connect( mDstText, SIGNAL(textChanged()), this, SLOT(dstChanged()));
    connect( mKEKText, SIGNAL(textChanged(const QString&)), this, SLOT(kekChanged(const QString&)));

    connect( mGenKEKBtn, SIGNAL(clicked()), this, SLOT(clickKeyWrapGenKEK()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT( clickClearDataAll()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

KeyManDlg::~KeyManDlg()
{

}

void KeyManDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    mSaltTypeCombo->addItems( dataTypes );

    mKeyLenText->setText( "32" );
    mIterCntText->setText( "1024" );

    mSrcTypeCombo->addItems( kValueTypeList );
    mSrcTypeCombo->setCurrentIndex(1);

    mKEKTypeCombo->addItems( kValueTypeList );
    mKEKTypeCombo->setCurrentIndex(1);

    mDstTypeCombo->addItems( kValueTypeList );
    mDstTypeCombo->setCurrentIndex(1);

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
        berApplet->warningBox( tr( "Enter a passphrase"), this );
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
    int nPad = 0;

    QString strInput = mSrcText->toPlainText();
    QString strWrappingKey = mKEKText->text();
    QString strOutput;

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( "Enter input data", this );
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "Enter wrapping key data", this );
        goto end;
    }

    if( mKWPRadio->isChecked() )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mSrcTypeCombo->currentText(), strInput );
    getBINFromString( &binWrappingKey, mKEKTypeCombo->currentText(), strWrappingKey );

    ret = JS_PKI_WrapKey( nPad, &binWrappingKey, &binInput, &binOutput );

    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to wrap key: %1").arg(ret), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, mDstTypeCombo->currentText() );
    mDstText->setPlainText( strOutput );

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
    int nPad = 0;

    QString strInput = mSrcText->toPlainText();
    QString strWrappingKey = mKEKText->text();
    QString strOutput;

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( "Enter input data", this );
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "Enter wrapping key data", this );
        goto end;
    }

    if( mKWPRadio->isChecked() )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mSrcTypeCombo->currentText(), strInput );
    getBINFromString( &binWrappingKey, mKEKTypeCombo->currentText(), strWrappingKey );

    ret = JS_PKI_UnwrapKey( nPad, &binWrappingKey, &binInput, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to unwrap key: %1").arg(ret), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, mDstTypeCombo->currentText() );
    mDstText->setPlainText( strOutput );

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

 void KeyManDlg::clickKeyWrapGenKEK()
 {
     BIN binKEK = {0,0};
     mKEKTypeCombo->setCurrentIndex(1);
     JS_PKI_genRandom( 16, &binKEK );
     mKEKText->setText( getHexString( &binKEK ) );
     JS_BIN_reset( &binKEK );
 }

void KeyManDlg::clickChange()
{
    QString strDst = mDstText->toPlainText();
    mSrcTypeCombo->setCurrentText( mDstTypeCombo->currentText() );

    mSrcText->setPlainText( strDst );
    mDstText->clear();
}

void KeyManDlg::clickOutputClear()
{
    mOutputText->clear();
}

void KeyManDlg::srcChanged()
{
    QString strSrc = mSrcText->toPlainText();
    int nLen = getDataLen( mSrcTypeCombo->currentText(), strSrc );
    mSrcLenText->setText( QString("%1").arg(nLen));
}

void KeyManDlg::dstChanged()
{
    QString strDst = mDstText->toPlainText();
    int nLen = getDataLen( mDstTypeCombo->currentText(), strDst );
    mDstLenText->setText( QString("%1").arg(nLen));
}

void KeyManDlg::kekChanged( const QString& text )
{
    QString strKEK = mKEKText->text();
    int nLen = getDataLen( mKEKTypeCombo->currentText(), strKEK );
    mKEKLenText->setText( QString("%1").arg(nLen));
}

void KeyManDlg::clickClearDataAll()
{
    mPasswordText->clear();
    mSaltText->clear();
    mIterCntText->clear();
    mKeyLenText->clear();
    mOutputText->clear();

    mSrcText->clear();
    mKEKText->clear();
    mDstText->clear();
}
