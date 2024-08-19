/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

    connect( mPBKDF2Radio, SIGNAL(clicked()), this, SLOT(checkPBKDF()));
    connect( mHKDFRadio, SIGNAL(clicked()), this, SLOT(checkHKDF()));
    connect( mANSX963Radio, SIGNAL(clicked()), this, SLOT(checkX963()));

    connect( mMakeKeyBtn, SIGNAL(clicked()), this, SLOT(clickMakeKey()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(keyValueChanged()));

    connect( mSecretText, SIGNAL(textChanged(const QString&)), this, SLOT(secretChanged()));
    connect( mSecretTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(secretChanged()));
    connect( mInfoText, SIGNAL(textChanged(QString)), this, SLOT(infoChanged()));
    connect( mInfoTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(infoChanged()));
    connect( mSaltText, SIGNAL(textChanged()), this, SLOT(saltChanged()));
    connect( mSaltTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(saltChanged()));

    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    connect( mWrapBtn, SIGNAL(clicked()), this, SLOT(clickWrap()));
    connect( mUnwrapBtn, SIGNAL(clicked()), this, SLOT(clickUnwrap()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcChanged()));
    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));
    connect( mDstText, SIGNAL(textChanged()), this, SLOT(dstChanged()));
    connect( mKEKTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(kekChanged()));
    connect( mKEKText, SIGNAL(textChanged(const QString&)), this, SLOT(kekChanged()));

    connect( mGenKEKBtn, SIGNAL(clicked()), this, SLOT(clickKeyWrapGenKEK()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT( clickClearDataAll()));

    initialize();
    mMakeKeyBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDeriveTab->layout()->setSpacing(5);
    mDeriveTab->layout()->setMargin(5);

    mWrapTab->layout()->setSpacing(5);
    mWrapTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyManDlg::~KeyManDlg()
{

}

void KeyManDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    mSecretTypeCombo->addItems( dataTypes );
    mInfoTypeCombo->addItems( dataTypes );
    mSaltTypeCombo->addItems( dataTypes );

    mKeyLenText->setText( "32" );
    mIterCntText->setText( "1024" );

    mSrcTypeCombo->addItems( kValueTypeList );
    mSrcTypeCombo->setCurrentIndex(1);

    mKEKTypeCombo->addItems( kValueTypeList );
    mKEKTypeCombo->setCurrentIndex(1);

    mDstTypeCombo->addItems( kValueTypeList );
    mDstTypeCombo->setCurrentIndex(1);

    mPBKDF2Radio->click();

    tabWidget->setCurrentIndex(0);
}

void KeyManDlg::clickMakeKey()
{
    int ret = 0;
    BIN binSecret = {0,0};
    BIN binSalt = { 0,0 };
    BIN binInfo = {0,0};
    BIN binKey = { 0, 0 };
    int nIter = 0;
    int nKeySize = 0;

    QString strSecret = mSecretText->text();

    if( strSecret.length() <= 0 )
    {
        berApplet->warningBox( tr( "Enter a secret or password"), this );
        return;
    }

    QString strHash = mHashCombo->currentText();
    nIter = mIterCntText->text().toInt();
    nKeySize = mKeyLenText->text().toInt();

    getBINFromString( &binSecret, mSecretTypeCombo->currentText(), strSecret );

    QString strSalt = mSaltText->toPlainText();
    getBINFromString( &binSalt, mSaltTypeCombo->currentText(), strSalt );

    QString strInfo = mInfoText->text();
    getBINFromString( &binInfo, mInfoTypeCombo->currentText(), strInfo );

    berApplet->logLine();

    if( mPBKDF2Radio->isChecked() )
    {
        ret = JS_PKI_PBKDF2( strSecret.toStdString().c_str(), &binSalt, nIter, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- PBKDF2" ));
        berApplet->logLine();
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
    }
    else if( mHKDFRadio->isChecked() )
    {
        ret = JS_PKI_KDF_HKDF( &binSecret, &binSalt, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- HKDF" ));
        berApplet->logLine();
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }
    else if( mANSX963Radio->isChecked() )
    {
        ret = JS_PKI_KDF_X963( &binSecret, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- ANS X963" ));
        berApplet->logLine();
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binKey, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );


        berApplet->log( QString( "Secret   : %1").arg( strSecret ));
        berApplet->log( QString( "Hash     : %1 | Iteration Count: %2").arg( strHash ).arg( nIter ));
        berApplet->log( QString( "Key      : %1" ).arg(getHexString(&binKey)));
        berApplet->logLine();
    }

    JS_BIN_reset( &binSecret );
    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binKey );

    repaint();
}

void KeyManDlg::secretChanged()
{
    QString strSecret = mSecretText->text();
    QString strLen = getDataLenString( mSecretTypeCombo->currentText(), strSecret );
    mSecretLenText->setText(QString("%1").arg(strLen));
}

void KeyManDlg::saltChanged()
{
    QString strSalt = mSaltText->toPlainText();
    QString strLen = getDataLenString( mSaltTypeCombo->currentText(), strSalt );
    mSaltLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::infoChanged()
{
    QString strInfo = mInfoText->text();
    QString strLen = getDataLenString( mInfoTypeCombo->currentText(), strInfo );
    mInfoLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::keyValueChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
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
        mSrcText->setFocus();
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "Enter KEK", this );
        mKEKText->setFocus();
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
        mSrcText->setFocus();
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        berApplet->warningBox( "Enter KEK", this );
        mKEKText->setFocus();
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

void KeyManDlg::checkPBKDF()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItem( "String" );

    mSecretLabel->setText( tr("Password"));

    mInfoGroup->setEnabled(false);
    mSaltGroup->setEnabled(true);
    mIterCntLabel->setEnabled(true);
    mIterCntText->setEnabled(true);
}

void KeyManDlg::checkHKDF()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItems( dataTypes );

    mSecretLabel->setText( tr("Secret"));

    mInfoGroup->setEnabled(true);
    mSaltGroup->setEnabled(true);
    mIterCntLabel->setEnabled(false);
    mIterCntText->setEnabled(false);
}

void KeyManDlg::checkX963()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItems( dataTypes );

    mSecretLabel->setText( tr("Secret"));

    mInfoGroup->setEnabled(true);
    mSaltGroup->setEnabled(false);
    mIterCntLabel->setEnabled(false);
    mIterCntText->setEnabled(false);
}

void KeyManDlg::clickOutputClear()
{
    mOutputText->clear();
}

void KeyManDlg::srcChanged()
{
    QString strSrc = mSrcText->toPlainText();
    QString strLen = getDataLenString( mSrcTypeCombo->currentText(), strSrc );
    mSrcLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::dstChanged()
{
    QString strDst = mDstText->toPlainText();
    QString strLen = getDataLenString( mDstTypeCombo->currentText(), strDst );
    mDstLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::kekChanged()
{
    QString strKEK = mKEKText->text();
    QString strLen = getDataLenString( mKEKTypeCombo->currentText(), strKEK );
    mKEKLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::clickClearDataAll()
{
    mSecretText->clear();
    mInfoText->clear();
    mSaltText->clear();
    mIterCntText->clear();
    mKeyLenText->clear();
    mOutputText->clear();

    mSrcText->clear();
    mKEKText->clear();
    mDstText->clear();
}
