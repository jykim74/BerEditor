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
#include "key_list_dlg.h"
#include "js_pqc.h"
#include "key_pair_man_dlg.h"
#include "js_error.h"

KeyManDlg::KeyManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mPBKDF2Radio, SIGNAL(clicked()), this, SLOT(checkPBKDF()));
    connect( mHKDFRadio, SIGNAL(clicked()), this, SLOT(checkHKDF()));
    connect( mANSX963Radio, SIGNAL(clicked()), this, SLOT(checkX963()));
    connect( mScryptRadio, SIGNAL(clicked()), this, SLOT(checkScrypt()));

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

    connect( mKEMClearAllBtn, SIGNAL(clicked()), this, SLOT(clickKEMClearAll()));
    connect( mKEMEncapBtn, SIGNAL(clicked(bool)), this, SLOT(clickKEMEncap()));
    connect( mKEMDecapBtn, SIGNAL(clicked()), this, SLOT(clickKEMDecap()));

    connect( mKEMKeyText, SIGNAL(textChanged()), this, SLOT(changeKEMKey()));
    connect( mKEMWrappedKeyText, SIGNAL(textChanged()), this, SLOT(changeKEMWrappedKey()));
    connect( mKEMDecKeyText, SIGNAL(textChanged()), this, SLOT(changeKEMDecKey()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT( clickClearDataAll()));

    initialize();
    mMakeKeyBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDeriveTab->layout()->setSpacing(5);
    mDeriveTab->layout()->setMargin(5);

    mWrapTab->layout()->setSpacing(5);
    mWrapTab->layout()->setMargin(5);

    mKeyEncapTab->layout()->setSpacing(5);
    mKeyEncapTab->layout()->setMargin(5);
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


    mSecretTypeCombo->addItems( kDataTypeList );
    mInfoTypeCombo->addItems( kDataTypeList );
    mSaltTypeCombo->addItems( kDataTypeList );

    mKeyLenText->setText( "32" );
    mIterCntText->setText( "1024" );
    mRText->setText( "8" );
    mPText->setText( "16" );

    mSrcTypeCombo->addItems( kValueTypeList );
    mSrcTypeCombo->setCurrentIndex(1);

    mKEKTypeCombo->addItems( kValueTypeList );
    mKEKTypeCombo->setCurrentIndex(1);

    mDstTypeCombo->addItems( kValueTypeList );
    mDstTypeCombo->setCurrentIndex(1);

    mPBKDF2Radio->click();

    mSrcText->setPlaceholderText( tr("Select KeyList key" ));
    mKEKText->setPlaceholderText( tr("Select KeyList key") );
    mSecretText->setPlaceholderText( tr( "Enter a password" ));


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
    int nR = 0;
    int nP = 0;

    QString strSecret = mSecretText->text();

    if( strSecret.length() <= 0 )
    {
        berApplet->warningBox( tr( "Enter a secret or password"), this );
        return;
    }

    QString strHash = mHashCombo->currentText();
    nIter = mIterCntText->text().toInt();
    nKeySize = mKeyLenText->text().toInt();
    nR = mRText->text().toInt();
    nP = mPText->text().toInt();

    getBINFromString( &binSecret, mSecretTypeCombo->currentText(), strSecret );

    QString strSalt = mSaltText->toPlainText();
    getBINFromString( &binSalt, mSaltTypeCombo->currentText(), strSalt );

    QString strInfo = mInfoText->text();
    getBINFromString( &binInfo, mInfoTypeCombo->currentText(), strInfo );

    berApplet->logLine();

    mOutputText->clear();

    if( mPBKDF2Radio->isChecked() )
    {
        ret = JS_PKI_PBKDF2( strSecret.toStdString().c_str(), &binSalt, nIter, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- PBKDF2" ));
        berApplet->logLine2();
        berApplet->log( QString( "Iter Cnt : %1" ).arg( nIter ));
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
    }
    else if( mHKDFRadio->isChecked() )
    {
        ret = JS_PKI_KDF_HKDF( &binSecret, &binSalt, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- HKDF" ));
        berApplet->logLine2();
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }
    else if( mANSX963Radio->isChecked() )
    {
        ret = JS_PKI_KDF_X963( &binSecret, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- ANS X963" ));
        berApplet->logLine2();
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }
    else if( mScryptRadio->isChecked() )
    {
        ret = JS_PKI_Scrypt( strSecret.toStdString().c_str(), &binSalt, nIter, nP, nR, nKeySize, &binKey );
        berApplet->log( QString( "-- Scrypt" ));
        berApplet->logLine2();
        berApplet->log( QString( "N        : %1" ).arg( nIter ));
        berApplet->log( QString( "R        : %1" ).arg( nR ));
        berApplet->log( QString( "P        : %1" ).arg( nP ));
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binKey, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );

        berApplet->log( QString( "Secret   : %1").arg( getHexString( &binSecret) ));
        berApplet->log( QString( "Hash     : %1").arg( strHash ));
        berApplet->log( QString( "Key      : %1" ).arg(getHexString(&binKey)));
        berApplet->logLine();
    }
    else
    {
        berApplet->warnLog( tr( "fail to make key: %1").arg(ret), this );
    }

    JS_BIN_reset( &binSecret );
    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binKey );

    update();
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
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key for source" ));
        keyList.setManage(false);

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mSrcTypeCombo->setCurrentText( "Hex" );
                strInput = strKey;
                mSrcText->setPlainText( strInput );
            }
        }

        if( strInput.length() < 1 )
        {
            berApplet->warningBox( "Enter input data", this );
            mSrcText->setFocus();
            goto end;
        }
    }

    if( strWrappingKey.length() < 1 )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key for KEK" ));
        keyList.setManage(false);
        keyList.mKeyTypeCombo->setCurrentText( "AES" );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKEKTypeCombo->setCurrentText( "Hex" );
                strWrappingKey = strKey;
                mKEKText->setText( strWrappingKey );
            }
        }

        if( strWrappingKey.length() < 1 )
        {
            berApplet->warningBox( "Enter KEK", this );
            mKEKText->setFocus();
            goto end;
        }
    }

    if( mKWPRadio->isChecked() )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mSrcTypeCombo->currentText(), strInput );
    if( nPad == 0 )
    {
        if( binInput.nLen < 16 )
        {
            berApplet->warningBox( tr("Must be 16 bytes or more in KW mode"), this );
            mInfoText->setFocus();
            goto end;
        }
    }

    getBINFromString( &binWrappingKey, mKEKTypeCombo->currentText(), strWrappingKey );

    berApplet->logLine();
    berApplet->log( QString( "-- Wrap Key (%1)" ).arg( mKWRadio->isChecked() ? "KW" : "KWP" ) );

    ret = JS_PKI_WrapKey( nPad, &binWrappingKey, &binInput, &binOutput );

    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to wrap key: %1").arg(ret), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, mDstTypeCombo->currentText() );
    mDstText->setPlainText( strOutput );

    berApplet->logLine2();
    berApplet->log( QString( "Input Key   : %1" ).arg(getHexString(&binInput)));
    berApplet->log( QString( "KEK         : %1" ).arg( getHexString( &binWrappingKey)));
    berApplet->log( QString( "Wrapped Key : %1" ).arg( getHexString(&binOutput)));
    berApplet->logLine();

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
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key for KEK" ));
        keyList.setManage(false);
        keyList.mKeyTypeCombo->setCurrentText( "AES" );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKEKTypeCombo->setCurrentText( "Hex" );
                strWrappingKey = strKey;
                mKEKText->setText( strWrappingKey );
            }
        }

        if( strWrappingKey.length() < 1 )
        {
            berApplet->warningBox( "Enter KEK", this );
            mKEKText->setFocus();
            goto end;
        }
    }

    if( mKWPRadio->isChecked() )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mSrcTypeCombo->currentText(), strInput );
    getBINFromString( &binWrappingKey, mKEKTypeCombo->currentText(), strWrappingKey );

    berApplet->logLine();
    berApplet->log( QString( "-- Unwrap Key (%1)" ).arg( mKWRadio->isChecked() ? "KW" : "KWP" ) );


    ret = JS_PKI_UnwrapKey( nPad, &binWrappingKey, &binInput, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to unwrap key: %1").arg(ret), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, mDstTypeCombo->currentText() );
    mDstText->setPlainText( strOutput );

    berApplet->logLine2();
    berApplet->log( QString( "Input Key      : %1" ).arg(getHexString(&binInput)));
    berApplet->log( QString( "KEK            : %1" ).arg( getHexString( &binWrappingKey)));
    berApplet->log( QString( "Unwrapped Key  : %1" ).arg( getHexString(&binOutput)));
    berApplet->logLine();

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
    mHashLabel->setEnabled(true);
    mHashCombo->setEnabled( true );
    mIterCntLabel->setEnabled(true);
    mIterCntText->setEnabled(true);
    mRLabel->setEnabled(false);
    mRText->setEnabled(false);
    mPLabel->setEnabled(false);
    mPText->setEnabled(false);
}

void KeyManDlg::checkHKDF()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItems( kDataTypeList );

    mSecretLabel->setText( tr("Secret"));

    mInfoGroup->setEnabled(true);
    mSaltGroup->setEnabled(true);
    mHashLabel->setEnabled(true);
    mHashCombo->setEnabled( true );
    mIterCntLabel->setEnabled(false);
    mIterCntText->setEnabled(false);
    mRLabel->setEnabled(false);
    mRText->setEnabled(false);
    mPLabel->setEnabled(false);
    mPText->setEnabled(false);
}

void KeyManDlg::checkX963()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItems( kDataTypeList );

    mSecretLabel->setText( tr("Secret"));

    mInfoGroup->setEnabled(true);
    mSaltGroup->setEnabled(false);
    mHashLabel->setEnabled(true);
    mHashCombo->setEnabled( true );
    mIterCntLabel->setEnabled(false);
    mIterCntText->setEnabled(false);
    mRLabel->setEnabled(false);
    mRText->setEnabled(false);
    mPLabel->setEnabled(false);
    mPText->setEnabled(false);
}

void KeyManDlg::checkScrypt()
{
    mSecretTypeCombo->clear();
    mSecretTypeCombo->addItem( "String" );

    mSecretLabel->setText( tr("Password"));

    mInfoGroup->setEnabled(false);
    mSaltGroup->setEnabled(true);
    mHashLabel->setEnabled(false);
    mHashCombo->setEnabled( false );
    mIterCntLabel->setEnabled(true);
    mIterCntText->setEnabled(true);
    mRLabel->setEnabled(true);
    mRText->setEnabled(true);
    mPLabel->setEnabled(true);
    mPText->setEnabled(true);
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

    clickKEMClearAll();
}

void KeyManDlg::clickKEMClearAll()
{
    mKEMKeyText->clear();
    mKEMWrappedKeyText->clear();
    mKEMDecKeyText->clear();
}

void KeyManDlg::clickKEMEncap()
{
    int ret = -1;
    QString strPubPath;

    BIN binPub = {0,0};
    BIN binWrappedKey = {0,0};
    BIN binKey = {0,0};

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
    {
        ret = -1;
        goto end;
    }

    strPubPath = keyPairMan.getPubPath();
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

    ret = JS_ML_KEM_encapsulate( &binPub, &binWrappedKey, &binKey );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to encapsulate: %1" ).arg( JERR(ret) ), this );
        goto end;
    }

    mKEMKeyText->setPlainText( getHexString( &binKey ));
    mKEMWrappedKeyText->setPlainText( getHexString( &binWrappedKey ));

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binWrappedKey );
}

void KeyManDlg::clickKEMDecap()
{
    int ret = -1;

    BIN binPri = {0,0};
    BIN binWrappedKey = {0,0};
    BIN binDecKey = {0,0};

    QString strWrappedKey = mKEMWrappedKeyText->toPlainText();
    if( strWrappedKey.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a wrapped key" ), this );
        mKEMWrappedKeyText->setFocus();
        return;
    }

    QString strPriPath;

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        goto end;

    strPriPath = keyPairMan.getPriPath();

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );

//    JS_BIN_decodeHex( strEncKey.toStdString().c_str(), &binEncKey );
    JS_BIN_decodeHex( strWrappedKey.toStdString().c_str(), &binWrappedKey );

    ret = JS_ML_KEM_decapsulate( &binPri, &binWrappedKey, &binDecKey );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to decapsulate: %1" ).arg( JERR(ret) ), this );
        goto end;
    }

    mKEMDecKeyText->setPlainText( getHexString( &binDecKey ));

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binWrappedKey );
    JS_BIN_reset( &binDecKey );
}

void KeyManDlg::changeKEMKey()
{
    QString strKey = mKEMKeyText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strKey );
    mKEMKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::changeKEMWrappedKey()
{
    QString strKey = mKEMWrappedKeyText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strKey );
    mKEMWrappedKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::changeKEMDecKey()
{
    QString strKey = mKEMDecKeyText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strKey );
    mKEMDecKeyLenText->setText( QString("%1").arg(strLen));
}
