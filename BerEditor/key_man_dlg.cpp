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
#include "cert_man_dlg.h"
#include "js_error.h"
#include "pri_key_info_dlg.h"
#include "js_pki_tools.h"
#include "cert_info_dlg.h"

static const QStringList kKW_Methods = { "KW", "KWP" };

KeyManDlg::KeyManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mKD_PBKDF2Radio, SIGNAL(clicked()), this, SLOT(checkKD_PBKDF()));
    connect( mKD_HKDFRadio, SIGNAL(clicked()), this, SLOT(checkKD_HKDF()));
    connect( mKD_ANSX963Radio, SIGNAL(clicked()), this, SLOT(checkKD_X963()));
    connect( mKD_ScryptRadio, SIGNAL(clicked()), this, SLOT(checkKD_Scrypt()));

    connect( mKD_DeriveKeyBtn, SIGNAL(clicked()), this, SLOT(clickKD_DeriveKey()));
    connect( mKD_OutputText, SIGNAL(textChanged()), this, SLOT(changeKD_Output()));

    connect( mKD_SecretText, SIGNAL(textChanged(const QString&)), this, SLOT(changeKD_Secret()));
    connect( mKD_SecretTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKD_Secret()));
    connect( mKD_InfoText, SIGNAL(textChanged(QString)), this, SLOT(changeKD_Info()));
    connect( mKD_InfoTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKD_Info()));
    connect( mKD_SaltText, SIGNAL(textChanged()), this, SLOT(changeKD_Salt()));
    connect( mKD_SaltTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKD_Salt()));

    connect( mKD_SaltClearBtn, SIGNAL(clicked()), this, SLOT(clickKD_SaltClear()));
    connect( mKD_OutputClearBtn, SIGNAL(clicked()), this, SLOT(clickKD_OutputClear()));

    connect( mKW_KeyWrapRadio, SIGNAL(clicked()), this, SLOT(checkKW_KeyWrap()));
    connect( mKW_KeyUnwrapRadio, SIGNAL(clicked()), this, SLOT(checkKW_KeyUnwrap()));
    connect( mKW_RunBtn, SIGNAL(clicked()), this, SLOT(clickKW_Run()));
    connect( mKW_SrcClearBtn, SIGNAL(clicked()), this, SLOT(clickKW_SrcClear()));
    connect( mKW_KEKClearBtn, SIGNAL(clicked()), this, SLOT(clickKW_KEKClear()));
    connect( mKW_DstClearBtn, SIGNAL(clicked()), this, SLOT(clickKW_DstClear()));
    connect( mKW_ChangeBtn, SIGNAL(clicked()), this, SLOT(clickKW_Change()));

    connect( mKW_SrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(chageKW_Src()));
    connect( mKW_SrcText, SIGNAL(textChanged()), this, SLOT(chageKW_Src()));
    connect( mKW_DstText, SIGNAL(textChanged()), this, SLOT(chageKW_Dst()));
    connect( mKW_KEKTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKW_KEK()));
    connect( mKW_KEKText, SIGNAL(textChanged(const QString&)), this, SLOT(changeKW_KEK()));

    connect( mKW_GenKEKBtn, SIGNAL(clicked()), this, SLOT(clickKW_GenKEK()));

    connect( mKEMEncapRadio, SIGNAL(clicked()), this, SLOT(checkKEMEncap()));
    connect( mKEMDecapRadio, SIGNAL(clicked()), this, SLOT(checkKEMDecap()));
    connect( mKEMRunBtn, SIGNAL(clicked()), this, SLOT(clickKEMRun()));

    connect( mKEMKeyText, SIGNAL(textChanged()), this, SLOT(changeKEMKey()));
    connect( mKEMWrappedKeyText, SIGNAL(textChanged()), this, SLOT(changeKEMWrappedKey()));
    connect( mKEMPriKeyEncryptedCheck, SIGNAL(clicked()), this, SLOT(checkKEMPriKeyEncrypted()));

    connect( mKEMWrappedKeyClearBtn, SIGNAL(clicked()), this, SLOT(clickKEMWrappedKeyClear()));
    connect( mKEMKeyClearBtn, SIGNAL(clicked()), this, SLOT(clickKEMKeyClear()));

    connect( mKEMPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(clickKEMPriKeyFind()));
    connect( mKEMPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickKEMPriKeyView()));
    connect( mKEMPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickKEMPriKeyDecode()));
    connect( mKEMPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickKEMPriKeyType()));

    connect( mKEMCertFindBtn, SIGNAL(clicked()), this, SLOT(clickKEMCertFind()));
    connect( mKEMCertViewBtn, SIGNAL(clicked()), this, SLOT(clickKEMCertView()));
    connect( mKEMCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickKEMCertDecode()));
    connect( mKEMCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickKEMCertType()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT( clickClearDataAll()));

    initialize();
    mKD_DeriveKeyBtn->setDefault(true);
    mKD_SecretText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mKD_SaltClearBtn->setFixedWidth(34);
    mKD_OutputClearBtn->setFixedWidth(34);

    mKW_SrcClearBtn->setFixedWidth(34);
    mKW_KEKClearBtn->setFixedWidth(34);
    mKW_DstClearBtn->setFixedWidth(34);

    mKEMWrappedKeyClearBtn->setFixedWidth(34);
    mKEMKeyClearBtn->setFixedWidth(34);

    mDeriveTab->layout()->setSpacing(5);
    mDeriveTab->layout()->setMargin(5);

    mWrapTab->layout()->setSpacing(5);
    mWrapTab->layout()->setMargin(5);

    mKeyEncapTab->layout()->setSpacing(5);
    mKeyEncapTab->layout()->setMargin(5);

    mKEMPriKeyDecodeBtn->setFixedWidth(34);
    mKEMPriKeyTypeBtn->setFixedWidth(34);
    mKEMPriKeyViewBtn->setFixedWidth(34);

    mKEMCertDecodeBtn->setFixedWidth(34);
    mKEMCertTypeBtn->setFixedWidth(34);
    mKEMCertViewBtn->setFixedWidth(34);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyManDlg::~KeyManDlg()
{

}

void KeyManDlg::initUI()
{
    mKD_SecretTypeCombo->addItems( kDataTypeList );
    mKD_InfoTypeCombo->addItems( kDataTypeList );
    mKD_SaltTypeCombo->addItems( kDataTypeList );

    mKW_MethodCombo->addItems( kKW_Methods );
    mKW_SrcTypeCombo->addItems( kDataTypeList );
    mKW_KEKTypeCombo->addItems( kDataTypeList );

    mKD_KeyLenText->setText( "32" );
    mKD_IterCntText->setText( "1024" );
    mKD_NText->setText( "1024" );
    mKD_RText->setText( "8" );
    mKD_PText->setText( "16" );

    mKW_SrcText->setPlaceholderText( tr("Source key hex value" ));
    mKW_KEKText->setPlaceholderText( tr("Select KeyList key") );
    mKW_DstText->setPlaceholderText( tr( "Hex value" ) );
    mKD_SecretText->setPlaceholderText( tr( "Enter a password" ));
    mKD_OutputText->setPlaceholderText( tr( "Hex value" ));

    mKEMPriKeyPathText->setPlaceholderText( tr("Select a private key" ));
    mKEMCertPathText->setPlaceholderText( tr("Select a certificate or public key") );

    mKEMWrappedKeyText->setPlaceholderText( tr("Hex value" ));
    mKEMKeyText->setPlaceholderText( tr( "Hex value" ));

    checkKEMPriKeyEncrypted();
}

void KeyManDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mKD_HashCombo->addItems( kHashList );
    mKD_HashCombo->setCurrentText( setMgr->defaultHash() );

    mKD_PBKDF2Radio->click();
    mKEMEncapRadio->click();

    tabWidget->setCurrentIndex(0);
}

int KeyManDlg::readKEMPrivateKey( BIN *pPriKey )
{
    int ret = -1;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};

    QString strPriPath = mKEMPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mKEMPriKeyPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        mKEMPriKeyPathText->setFocus();
        return  -1;
    }

    if( mKEMPriKeyEncryptedCheck->isChecked() )
    {
        QString strPasswd = mKEMPriKeyPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            mKEMPriKeyPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binSrc, NULL, &binPri );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "failed to decrypt private key:%1").arg( ret ), this );
            mKEMPriKeyPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_copy( pPriKey, &binPri );
    }
    else
    {
        JS_BIN_copy( pPriKey, &binSrc );
    }

    ret = JSR_OK;

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );

    return ret;
}

int KeyManDlg::getKEMPrivateKey( BIN *pPriKey )
{
    int ret = -1;

    if( mKEMGroup->isChecked() == true )
    {
        ret = readKEMPrivateKey( pPriKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        if( mKEMUseCertManCheck->isChecked() == true )
        {
            CertManDlg certMan;
            QString strPriHex;
            certMan.setMode(ManModeSelBoth );
            certMan.setTitle( tr( "Select a private key") );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            strPriHex = certMan.getPriKeyHex();
            JS_BIN_decodeHex( strPriHex.toStdString().c_str(), pPriKey );
        }
        else
        {
            QString strPriPath;

            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select a private key" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                goto end;

            strPriPath = keyPairMan.getPriPath();

            JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pPriKey );
        }
    }

    ret = JSR_OK;
end :

    return ret;
}

int KeyManDlg::getKEMPublicKey( BIN *pPubKey )
{
    int ret = -1;
    BIN binCert = {0,0};
    int nType = -1;

    if( mKEMGroup->isChecked() == true )
    {
        if( mKEMCertPathText->text().isEmpty() )
        {
            berApplet->warningBox( tr( "Select a certificate"), this );
            mKEMCertPathText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_fileReadBER( mKEMCertPathText->text().toLocal8Bit().toStdString().c_str(), &binCert );
        if( JS_PKI_isCert( &binCert ) == 0 )
        {
            JS_BIN_copy( pPubKey, &binCert );
        }
        else
        {
            JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        }
    }
    else
    {
        if( mKEMUseCertManCheck->isChecked() == true )
        {
            CertManDlg certMan;
            QString strCertHex;

            certMan.setMode(ManModeSelCert);
            certMan.setTitle( tr( "Select a certificate") );

            if( certMan.exec() != QDialog::Accepted )
            {
                ret = -1;
                goto end;
            }

            strCertHex = certMan.getCertHex();
            JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        }
        else
        {
            QString strPubPath;

            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select a public key" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
            {
                ret = -1;
                goto end;
            }

            strPubPath = keyPairMan.getPubPath();
            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), pPubKey );
        }
    }

    ret = JSR_OK;

end :
    JS_BIN_reset( &binCert );

    return ret;
}


void KeyManDlg::clickKD_DeriveKey()
{
    int ret = 0;
    BIN binSecret = {0,0};
    BIN binSalt = { 0,0 };
    BIN binInfo = {0,0};
    BIN binKey = { 0, 0 };
    int nIter = 0;
    int nKeySize = 0;
    int nN = 0;
    int nR = 0;
    int nP = 0;

    QString strSecret = mKD_SecretText->text();

    if( strSecret.length() <= 0 )
    {
        berApplet->warningBox( tr( "Enter a secret or password"), this );
        mKD_SecretText->setFocus();
        return;
    }

    QString strHash = mKD_HashCombo->currentText();
    QString strInfo;

    nIter = mKD_IterCntText->text().toInt();
    nKeySize = mKD_KeyLenText->text().toInt();

    nN = mKD_NText->text().toInt();
    nR = mKD_RText->text().toInt();
    nP = mKD_PText->text().toInt();

    getBINFromString( &binSecret, mKD_SecretTypeCombo->currentText(), strSecret );

    QString strSalt = mKD_SaltText->toPlainText();

    getBINFromString( &binSalt, mKD_SaltTypeCombo->currentText(), strSalt );
    if( mKD_HKDFRadio->isChecked() == true )
    {
        if( binSalt.nLen <= 0 )
        {
            berApplet->warningBox( tr( "Enter a salt" ), this );
            mKD_SaltText->setFocus();
            goto end;
        }
    }

    strInfo = mKD_InfoText->text();
    getBINFromString( &binInfo, mKD_InfoTypeCombo->currentText(), strInfo );

    berApplet->logLine();

    mKD_OutputText->clear();

    if( mKD_PBKDF2Radio->isChecked() )
    {
        ret = JS_PKI_PBKDF2( strSecret.toStdString().c_str(), &binSalt, nIter, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- PBKDF2" ));
        berApplet->logLine2();
        berApplet->log( QString( "Iter Cnt : %1" ).arg( nIter ));
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
    }
    else if( mKD_HKDFRadio->isChecked() )
    {
        ret = JS_PKI_KDF_HKDF( &binSecret, &binSalt, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- HKDF" ));
        berApplet->logLine2();
        berApplet->log( QString( "Salt     : %1" ).arg(getHexString(&binSalt)));
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }
    else if( mKD_ANSX963Radio->isChecked() )
    {
        ret = JS_PKI_KDF_X963( &binSecret, &binInfo, strHash.toStdString().c_str(), nKeySize, &binKey );
        berApplet->log( QString( "-- ANS X963" ));
        berApplet->logLine2();
        berApplet->log( QString( "Info     : %1" ).arg(getHexString(&binInfo)));
    }
    else if( mKD_ScryptRadio->isChecked() )
    {
        ret = JS_PKI_Scrypt( strSecret.toStdString().c_str(), &binSalt, nN, nP, nR, nKeySize, &binKey );
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
        mKD_OutputText->setPlainText( pHex );
        if( pHex ) JS_free( pHex );

        berApplet->log( QString( "Secret   : %1").arg( getHexString( &binSecret) ));
        berApplet->log( QString( "Hash     : %1").arg( strHash ));
        berApplet->log( QString( "Key      : %1" ).arg(getHexString(&binKey)));
        berApplet->logLine();
    }
    else
    {
        berApplet->warnLog( tr( "fail to make key: %1").arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binSecret );
    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binKey );
}

void KeyManDlg::changeKD_Secret()
{
    QString strSecret = mKD_SecretText->text();
    QString strLen = getDataLenString( mKD_SecretTypeCombo->currentText(), strSecret );
    mKD_SecretLenText->setText(QString("%1").arg(strLen));
}

void KeyManDlg::changeKD_Salt()
{
    QString strSalt = mKD_SaltText->toPlainText();
    QString strLen = getDataLenString( mKD_SaltTypeCombo->currentText(), strSalt );
    mKD_SaltLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::changeKD_Info()
{
    QString strInfo = mKD_InfoText->text();
    QString strLen = getDataLenString( mKD_InfoTypeCombo->currentText(), strInfo );
    mKD_InfoLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::changeKD_Output()
{
    QString strLen = getDataLenString( DATA_HEX, mKD_OutputText->toPlainText() );
    mKD_OutputLenText->setText( QString("%1").arg(strLen));
}


void KeyManDlg::runKW_Wrap()
{
    int ret = 0;
    BIN binInput = {0,0};
    BIN binWrappingKey = {0,0};
    BIN binOutput = {0,0};
    int nPad = 0;

    QString strInput = mKW_SrcText->toPlainText();
    QString strWrappingKey = mKW_KEKText->text();
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
                mKW_SrcTypeCombo->setCurrentText( "Hex" );
                strInput = strKey;
                mKW_SrcText->setPlainText( strInput );
            }
        }

        if( strInput.length() < 1 )
        {
            berApplet->warningBox( "Enter input data", this );
            mKW_SrcText->setFocus();
            goto end;
        }
    }

    if( strWrappingKey.length() < 1 )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key for KEK" ));
        keyList.setManage(false);
        keyList.mKeyTypeCombo->setCurrentText( JS_PKI_KEY_NAME_AES );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKW_KEKTypeCombo->setCurrentText( "Hex" );
                strWrappingKey = strKey;
                mKW_KEKText->setText( strWrappingKey );
            }
        }

        if( strWrappingKey.length() < 1 )
        {
            berApplet->warningBox( "Enter KEK", this );
            mKW_KEKText->setFocus();
            goto end;
        }
    }

    if( mKW_MethodCombo->currentText() == "KWP" )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mKW_SrcTypeCombo->currentText(), strInput );
    if( nPad == 0 )
    {
        if( binInput.nLen < 16 )
        {
            berApplet->warningBox( tr("Must be 16 bytes or more in KW mode"), this );
            mKW_SrcText->setFocus();
            goto end;
        }
    }

    getBINFromString( &binWrappingKey, mKW_KEKTypeCombo->currentText(), strWrappingKey );

    berApplet->logLine();
    berApplet->log( QString( "-- Wrap Key (%1)" ).arg( mKW_MethodCombo->currentText() ));

    ret = JS_PKI_WrapKey( nPad, &binWrappingKey, &binInput, &binOutput );

    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to wrap key: %1").arg(JERR(ret)), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, DATA_HEX );
    mKW_DstText->setPlainText( strOutput );

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

void KeyManDlg::runKW_Unwrap()
{
    int ret = 0;
    BIN binInput = {0,0};
    BIN binWrappingKey = {0,0};
    BIN binOutput = {0,0};
    int nPad = 0;

    QString strInput = mKW_SrcText->toPlainText();
    QString strWrappingKey = mKW_KEKText->text();
    QString strOutput;

    if( strInput.length() < 1 )
    {
        berApplet->warningBox( "Enter input data", this );
        mKW_SrcText->setFocus();
        goto end;
    }

    if( strWrappingKey.length() < 1 )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key for KEK" ));
        keyList.setManage(false);
        keyList.mKeyTypeCombo->setCurrentText( JS_PKI_KEY_NAME_AES );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKW_KEKTypeCombo->setCurrentText( "Hex" );
                strWrappingKey = strKey;
                mKW_KEKText->setText( strWrappingKey );
            }
        }

        if( strWrappingKey.length() < 1 )
        {
            berApplet->warningBox( "Enter KEK", this );
            mKW_KEKText->setFocus();
            goto end;
        }
    }

    if( mKW_MethodCombo->currentText() == "KWP" )
        nPad = 1;
    else
        nPad = 0;

    getBINFromString( &binInput, mKW_SrcTypeCombo->currentText(), strInput );
    getBINFromString( &binWrappingKey, mKW_KEKTypeCombo->currentText(), strWrappingKey );

    berApplet->logLine();
    berApplet->log( QString( "-- Unwrap Key (%1)" ).arg( mKW_MethodCombo->currentText() ) );


    ret = JS_PKI_UnwrapKey( nPad, &binWrappingKey, &binInput, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( QString( "failed to unwrap key: %1").arg(JERR(ret)), this );
        goto end;
    }

    strOutput = getStringFromBIN( &binOutput, DATA_HEX );
    mKW_DstText->setPlainText( strOutput );

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

void KeyManDlg::checkKW_KeyWrap()
{
    mKW_HeadLabel->setText( tr("Key Wrap" ) );

    mKW_SrcText->setPlaceholderText( tr("Source key hex value") );
    mKW_SrcLabel->setText( tr( "Source key" ) );
    mKW_OutputLabel->setText( tr( "Wrapped key" ));
}

void KeyManDlg::checkKW_KeyUnwrap()
{
    mKW_HeadLabel->setText( tr("Key Unwrap" ) );

    mKW_SrcText->setPlaceholderText( tr("Wrapped key hex value") );
    mKW_SrcLabel->setText( tr( "Wrapped key" ) );
    mKW_OutputLabel->setText( tr( "Source key" ) );
}

void KeyManDlg::clickKW_Run()
{
    QString strMethod = mKW_MethodCombo->currentText();

    if( mKW_KeyWrapRadio->isChecked() == true )
        runKW_Wrap();
    else
        runKW_Unwrap();
}

void KeyManDlg::clickKW_SrcClear()
{
    mKW_SrcText->clear();
}

void KeyManDlg::clickKW_KEKClear()
{
    mKW_KEKText->clear();
}

void KeyManDlg::clickKW_DstClear()
{
    mKW_DstText->clear();
}

 void KeyManDlg::clickKW_GenKEK()
 {
     BIN binKEK = {0,0};
     mKW_KEKTypeCombo->setCurrentIndex(1);
     JS_PKI_genRandom( 16, &binKEK );
     mKW_KEKText->setText( getHexString( &binKEK ) );
     JS_BIN_reset( &binKEK );
 }

void KeyManDlg::clickKW_Change()
{
    QString strDst = mKW_DstText->toPlainText();
    mKW_SrcTypeCombo->setCurrentText( kDataHex );

    mKW_SrcText->setPlainText( strDst );
    mKW_DstText->clear();
}

void KeyManDlg::checkKD_PBKDF()
{
    mKD_SecretTypeCombo->clear();
    mKD_SecretTypeCombo->addItem( "String" );

    mKD_SecretLabel->setText( tr("Password"));

    mKD_InfoGroup->setEnabled(false);
    mKD_SaltGroup->setEnabled(true);
    mKD_HashLabel->setEnabled(true);
    mKD_HashCombo->setEnabled( true );
    mKD_IterCntLabel->setEnabled(true);
    mKD_IterCntText->setEnabled(true);

    mKD_NLabel->setEnabled(false);
    mKD_NText->setEnabled(false);
    mKD_RLabel->setEnabled(false);
    mKD_RText->setEnabled(false);
    mKD_PLabel->setEnabled(false);
    mKD_PText->setEnabled(false);
}

void KeyManDlg::checkKD_HKDF()
{
    mKD_SecretTypeCombo->clear();
    mKD_SecretTypeCombo->addItems( kDataTypeList );

    mKD_SecretLabel->setText( tr("Secret"));

    mKD_InfoGroup->setEnabled(true);
    mKD_SaltGroup->setEnabled(true);
    mKD_HashLabel->setEnabled(true);
    mKD_HashCombo->setEnabled( true );
    mKD_IterCntLabel->setEnabled(false);
    mKD_IterCntText->setEnabled(false);

    mKD_NLabel->setEnabled(false);
    mKD_NText->setEnabled(false);
    mKD_RLabel->setEnabled(false);
    mKD_RText->setEnabled(false);
    mKD_PLabel->setEnabled(false);
    mKD_PText->setEnabled(false);
}

void KeyManDlg::checkKD_X963()
{
    mKD_SecretTypeCombo->clear();
    mKD_SecretTypeCombo->addItems( kDataTypeList );

    mKD_SecretLabel->setText( tr("Secret"));

    mKD_InfoGroup->setEnabled(true);
    mKD_SaltGroup->setEnabled(false);
    mKD_HashLabel->setEnabled(true);
    mKD_HashCombo->setEnabled( true );
    mKD_IterCntLabel->setEnabled(false);
    mKD_IterCntText->setEnabled(false);
    mKD_NLabel->setEnabled(false);
    mKD_NText->setEnabled(false);
    mKD_RLabel->setEnabled(false);
    mKD_RText->setEnabled(false);
    mKD_PLabel->setEnabled(false);
    mKD_PText->setEnabled(false);
}

void KeyManDlg::checkKD_Scrypt()
{
    mKD_SecretTypeCombo->clear();
    mKD_SecretTypeCombo->addItem( "String" );

    mKD_SecretLabel->setText( tr("Password"));

    mKD_InfoGroup->setEnabled(false);
    mKD_SaltGroup->setEnabled(true);
    mKD_HashLabel->setEnabled(false);
    mKD_HashCombo->setEnabled( false );
    mKD_IterCntLabel->setEnabled(false);
    mKD_IterCntText->setEnabled(false);

    mKD_NLabel->setEnabled(true);
    mKD_NText->setEnabled(true);
    mKD_RLabel->setEnabled(true);
    mKD_RText->setEnabled(true);
    mKD_PLabel->setEnabled(true);
    mKD_PText->setEnabled(true);
}

void KeyManDlg::clickKD_SaltClear()
{
    mKD_SaltText->clear();
}

void KeyManDlg::clickKD_OutputClear()
{
    mKD_OutputText->clear();
}

void KeyManDlg::chageKW_Src()
{
    QString strSrc = mKW_SrcText->toPlainText();
    QString strLen = getDataLenString( mKW_SrcTypeCombo->currentText(), strSrc );
    mKW_SrcLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::chageKW_Dst()
{
    QString strDst = mKW_DstText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strDst );
    mKW_DstLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::changeKW_KEK()
{
    QString strKEK = mKW_KEKText->text();
    QString strLen = getDataLenString( mKW_KEKTypeCombo->currentText(), strKEK );
    mKW_KEKLenText->setText( QString("%1").arg(strLen));
}

void KeyManDlg::clickClearDataAll()
{
    mKD_SecretText->clear();
    mKD_InfoText->clear();
    mKD_SaltText->clear();
    mKD_OutputText->clear();

    mKW_SrcText->clear();
    mKW_KEKText->clear();
    mKW_DstText->clear();

    mKEMKeyText->clear();
    mKEMWrappedKeyText->clear();
}

void KeyManDlg::runKEMEncap()
{
    int ret = -1;
    int nKeyType = -1;
    QString strPubPath;

    BIN binPub = {0,0};
    BIN binWrappedKey = {0,0};
    BIN binKey = {0,0};

    ret = getKEMPublicKey( &binPub );
    if( ret != JSR_OK ) goto end;

    nKeyType = JS_PKI_getPubKeyType( &binPub );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_ML_KEM )
    {
        berApplet->warningBox(tr( "This key algorithm(%1) is not supported.")
                                  .arg( JS_PKI_getKeyAlgName( nKeyType )), this );

        goto end;
    }

    ret = JS_PKI_encapsulate( &binPub, &binWrappedKey, &binKey );
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

void KeyManDlg::runKEMDecap()
{
    int ret = -1;
    int nKeyType = -1;

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

    ret = getKEMPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_ML_KEM )
    {
        berApplet->warningBox(tr( "This key algorithm(%1) is not supported.")
                                  .arg( JS_PKI_getKeyAlgName( nKeyType )), this );

        goto end;
    }

    JS_BIN_decodeHex( strWrappedKey.toStdString().c_str(), &binWrappedKey );

    ret = JS_PKI_decapsulate( &binPri, &binWrappedKey, &binDecKey );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to decapsulate: %1" ).arg( JERR(ret) ), this );
        goto end;
    }

    mKEMKeyText->setPlainText( getHexString( &binDecKey ));

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binWrappedKey );
    JS_BIN_reset( &binDecKey );
}

void KeyManDlg::clickKEMRun()
{
    if( mKEMEncapRadio->isChecked() == true )
        runKEMEncap();
    else
        runKEMDecap();
}

void KeyManDlg::checkKEMPriKeyEncrypted()
{
    bool bVal = mKEMPriKeyEncryptedCheck->isChecked();
    mKEMPasswdLabel->setEnabled( bVal );
    mKEMPriKeyPasswdText->setEnabled( bVal );
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

void KeyManDlg::clickKEMWrappedKeyClear()
{
    mKEMWrappedKeyText->clear();
}

void KeyManDlg::clickKEMKeyClear()
{
    mKEMKeyText->clear();
}

void KeyManDlg::clickKEMPriKeyFind()
{
    QString strPath = mKEMPriKeyPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mKEMPriKeyPathText->setText(fileName);
}

void KeyManDlg::clickKEMPriKeyView()
{
    BIN binPri = {0,0};
    int nType = -1;

    PriKeyInfoDlg priKeyInfo;

    int ret = readKEMPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void KeyManDlg::clickKEMPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mKEMPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mKEMPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mKEMPriKeyPathText->setFocus();
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void KeyManDlg::clickKEMPriKeyType()
{
    BIN binPri = {0,0};
    int nType = -1;
    int ret = readKEMPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private Key Type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}


void KeyManDlg::clickKEMCertFind()
{
    QString strPath = mKEMCertPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mKEMCertPathText->setText(fileName);
}

void KeyManDlg::clickKEMCertView()
{
    BIN binCert = {0,0};
    QString strPath = mKEMCertPathText->text();


    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate or public key"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( binCert.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    if( JS_PKI_isCert( &binCert ) == 0 )
    {
        PriKeyInfoDlg priKeyInfo;
        priKeyInfo.setPublicKey( &binCert, strPath );
        priKeyInfo.exec();
    }
    else
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binCert, strPath );
        certInfo.exec();
    }

    JS_BIN_reset( &binCert );
}

void KeyManDlg::clickKEMCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mKEMCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a public key"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void KeyManDlg::clickKEMCertType()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strType;

    QString strPath = mKEMCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a certificate or public key"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mKEMCertPathText->setFocus();
        return;
    }

    if( JS_PKI_isCert( &binData ) == 1 )
    {
        strType = tr( "Certificate" );
        nType = JS_PKI_getCertKeyType( &binData );
    }
    else
    {
        strType = tr( "Public key" );
        nType = JS_PKI_getPubKeyType( &binData );
    }

    berApplet->messageBox( tr( "%1 type is %2").arg( strType ).arg( JS_PKI_getKeyAlgName( nType )), this);

    JS_BIN_reset( &binData );
}

void KeyManDlg::checkKEMEncap()
{
    mHeadLabel->setText( tr( "Key encapsulate" ) );
    mKEMKeyLabel->setText( tr( "Generated Key" ) );

    if( mKEMGroup->isChecked() == true )
    {
        setKEMEnableCert(true);
        setKEMEnablePriKey(false);
    }

    mKEMWrappedKeyText->setPlaceholderText( tr( "Generated at runtime" ));
}

void KeyManDlg::checkKEMDecap()
{
    mHeadLabel->setText( tr( "Key decapsulate" ) );
    mKEMKeyLabel->setText( tr( "Decrypted Key" ) );

    if( mKEMGroup->isChecked() == true )
    {
        setKEMEnableCert(false);
        setKEMEnablePriKey(true);
    }

    mKEMWrappedKeyText->setPlaceholderText( tr("Enter the wrapped key hex value") );
}

void KeyManDlg::setKEMEnableWrappedKey( bool bVal )
{
    mKEMWrappedKeyClearBtn->setEnabled(bVal);
    mKEMWrappedKeyLabel->setEnabled(bVal);
    mKEMWrappedKeyLenText->setEnabled(bVal);
    mKEMWrappedKeyText->setEnabled(bVal);
}

void KeyManDlg::setKEMEnableKey( bool bVal )
{
    mKEMKeyClearBtn->setEnabled(bVal);
    mKEMKeyLabel->setEnabled(bVal);
    mKEMKeyLenText->setEnabled(bVal);
    mKEMKeyText->setEnabled(bVal);
}

void KeyManDlg::setKEMEnableCert( bool bVal )
{
    mKEMCertDecodeBtn->setEnabled(bVal);
    mKEMCertFindBtn->setEnabled(bVal);
    mKEMCertLabel->setEnabled(bVal);
    mKEMCertPathText->setEnabled(bVal);
    mKEMCertTypeBtn->setEnabled(bVal);
    mKEMCertViewBtn->setEnabled(bVal);
}

void KeyManDlg::setKEMEnablePriKey( bool bVal )
{
    mKEMPriKeyDecodeBtn->setEnabled(bVal);
    mKEMPriKeyEncryptedCheck->setEnabled(bVal);
    mKEMPriKeyFindBtn->setEnabled(bVal);
    mKEMPriKeyLabel->setEnabled(bVal);
    mKEMPriKeyPasswdText->setEnabled(bVal);
    mKEMPriKeyPathText->setEnabled(bVal);
    mKEMPriKeyTypeBtn->setEnabled(bVal);
    mKEMPriKeyViewBtn->setEnabled(bVal);
}
