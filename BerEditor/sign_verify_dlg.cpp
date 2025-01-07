/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QFileInfo>
#include <QDateTime>
#include <QButtonGroup>

#include "sign_verify_dlg.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"
#include "js_error.h"
#include "common.h"
#include "sign_verify_thread.h"
#include "pri_key_info_dlg.h"

static QStringList algTypes = {
    "RSA",
    "ECDSA",
    "SM2",
    "Ed25519",
    "Ed448",
    "DSA"
};

static QStringList versionTypes = {
    "V15",
    "V21"
};

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    sctx_ = NULL;

    thread_ = NULL;
    update_cnt_ = 0;

    setupUi(this);
    initialize();

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mAlgTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));

    connect( mSignRadio, SIGNAL(clicked()), this, SLOT(clickSign()));
    connect( mVerifyRadio, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(signVerifyInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(signVerifyUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(signVerifyFinal()));

    connect( mAutoCertPubKeyCheck, SIGNAL(clicked()), this, SLOT(checkAutoCertOrPubKey()));
    connect( mPubKeyVerifyCheck, SIGNAL(clicked()), this, SLOT(checkPubKeyVerify()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyView()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

    connect( mUseKeyAlgCheck, SIGNAL(clicked()), this, SLOT(checkUseKeyAlg()));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyType()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickCertType()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(digestRun()));
    connect( mInputTab, SIGNAL(currentChanged(int)), this, SLOT(changeInputTab(int)));

    connect( mEncPrikeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));
    connect( mCertGroup, SIGNAL(clicked(bool)), this, SLOT(checkCertGroup()));

    mRunBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);

    mCertGroup->layout()->setSpacing(5);
    mCertGroup->layout()->setMargin(10);

    mPriKeyViewBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);
    mPriKeyDecodeBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mCertViewBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SignVerifyDlg::~SignVerifyDlg()
{
    if( sctx_ ) JS_PKI_signFree( &sctx_ );
    if( thread_ ) delete thread_;
}

void SignVerifyDlg::initialize()
{
    mAlgTypeCombo->addItems(algTypes);
    mHashTypeCombo->addItems(kHashList);
    mHashTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mVersionCombo->addItems(versionTypes);

    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mSignRadio );
    runGroup->addButton( mVerifyRadio );

    mAutoCertPubKeyCheck->setChecked(true);
    mUseKeyAlgCheck->setChecked(true);

    mInputTab->setCurrentIndex(0);

    checkAutoCertOrPubKey();
    checkUseKeyAlg();
    checkEncPriKey();
    mSignRadio->click();
}

int SignVerifyDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPriKeyPath->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mPriKeyPath->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        mPriKeyPath->setFocus();
        return  -1;
    }

    if( mEncPrikeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "failed to decrypt private key:%1").arg( ret ), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_copy( pPriKey, &binDec );
        ret = 0;
    }
    else
    {
        JS_BIN_copy( pPriKey, &binData );
        ret = 0;
    }

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );

    return ret;
}

int SignVerifyDlg::getPrivateKey( BIN *pPriKey, int *pnType )
{
    int ret = -1;
    int nType = -1;

    QString strHash = mHashTypeCombo->currentText();

    if( mCertGroup->isChecked() == true )
    {
        ret = readPrivateKey( pPriKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        QString strPriHex;
        certMan.setMode(ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strPriHex = certMan.getPriKeyHex();
        JS_BIN_decodeHex( strPriHex.toStdString().c_str(), pPriKey );
    }

    if( mUseKeyAlgCheck->isChecked() )
    {
        nType = JS_PKI_getPriKeyType( pPriKey );
        berApplet->log( QString( "PriKey Type : %1").arg( getKeyTypeName( nType )));

        if( nType == JS_PKI_KEY_TYPE_RSA )
            mAlgTypeCombo->setCurrentText( "RSA" );
        else if( nType == JS_PKI_KEY_TYPE_ECC )
            mAlgTypeCombo->setCurrentText( "ECDSA" );
        else if( nType == JS_PKI_KEY_TYPE_SM2 )
            mAlgTypeCombo->setCurrentText( "SM2" );
        else if( nType == JS_PKI_KEY_TYPE_DSA )
            mAlgTypeCombo->setCurrentText( "DSA" );
        else if( nType == JS_PKI_KEY_TYPE_ED25519 )
            mAlgTypeCombo->setCurrentText( "Ed25519" );
        else if( nType == JS_PKI_KEY_TYPE_ED448 )
            mAlgTypeCombo->setCurrentText( "Ed448" );
    }
    else
    {
        if( mAlgTypeCombo->currentText() == "RSA" )
            nType = JS_PKI_KEY_TYPE_RSA;
        else if( mAlgTypeCombo->currentText() == "SM2" )
            nType = JS_PKI_KEY_TYPE_SM2;
        else if( mAlgTypeCombo->currentText() == "DSA" )
            nType = JS_PKI_KEY_TYPE_DSA;
        else if( mAlgTypeCombo->currentText() == "Ed25519" )
        {
            nType = JS_PKI_KEY_TYPE_ED25519;
        }
        else if( mAlgTypeCombo->currentText() == "Ed448" )
        {
            nType = JS_PKI_KEY_TYPE_ED448;
        }
        else
            nType = JS_PKI_KEY_TYPE_ECC;
    }

    if( nType == JS_PKI_KEY_TYPE_SM2 )
    {
        if( strHash != "SM3" )
        {
            QString strMsg = tr("SM2 Key have to use SM3 hash for signature. do you change hash as SM3?");
            bool bVal = berApplet->yesOrNoBox( strMsg, this, true );

            if( bVal == true )
            {
                strHash = "SM3";
                mHashTypeCombo->setCurrentText( strHash );
            }
        }
    }

    *pnType = nType;
    ret = JSR_OK;
end :

    return ret;
}

int SignVerifyDlg::getPublicKey( BIN *pPubKey, int *pnType )
{
    int ret = -1;
    BIN binCert = {0,0};
    int nType = -1;
    QString strHash = mHashTypeCombo->currentText();

    if( mCertGroup->isChecked() == true )
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "Select a certificate"), this );
            ret = -1;
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        QString strCertHex;

        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
        {
            ret = -1;
            goto end;
        }

        strCertHex = certMan.getCertHex();
        JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binCert );
    }
    if( mAutoCertPubKeyCheck->isChecked() )
    {
        if( JS_PKI_isCert( &binCert ) == 0 )
        {
            mPubKeyVerifyCheck->setChecked(true);
            JS_BIN_copy( pPubKey, &binCert );
        }
        else
        {
            mPubKeyVerifyCheck->setChecked(false);
            JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        }
    }
    else
    {
        if( mPubKeyVerifyCheck->isChecked() == false )
            JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        else
            JS_BIN_copy( pPubKey, &binCert );
    }

    if( mUseKeyAlgCheck->isChecked() )
    {
        nType = JS_PKI_getPubKeyType( pPubKey );
        berApplet->log( QString( "PubKey Type : %1").arg( getKeyTypeName( nType )));

        if( nType == JS_PKI_KEY_TYPE_RSA )
            mAlgTypeCombo->setCurrentText( "RSA" );
        else if( nType == JS_PKI_KEY_TYPE_SM2 )
            mAlgTypeCombo->setCurrentText( "SM2" );
        else if( nType == JS_PKI_KEY_TYPE_ECC )
            mAlgTypeCombo->setCurrentText( "ECDSA" );
        else if( nType == JS_PKI_KEY_TYPE_DSA )
            mAlgTypeCombo->setCurrentText( "DSA" );
        else if( nType == JS_PKI_KEY_TYPE_ED25519 )
            mAlgTypeCombo->setCurrentText( "Ed25519" );
        else if( nType == JS_PKI_KEY_TYPE_ED448 )
            mAlgTypeCombo->setCurrentText( "Ed448" );
    }
    else
    {
        if( mAlgTypeCombo->currentText() == "RSA" )
            nType = JS_PKI_KEY_TYPE_RSA;
        else if( mAlgTypeCombo->currentText() == "SM2" )
            nType = JS_PKI_KEY_TYPE_SM2;
        else if( mAlgTypeCombo->currentText() == "DSA" )
            nType = JS_PKI_KEY_TYPE_DSA;
        else if( mAlgTypeCombo->currentText() == "Ed25519" )
        {
            nType = JS_PKI_KEY_TYPE_ED25519;
        }
        else if( mAlgTypeCombo->currentText() == "Ed448" )
        {
            nType = JS_PKI_KEY_TYPE_ED448;
        }
        else
            nType = JS_PKI_KEY_TYPE_ECC;
    }

    if( nType == JS_PKI_KEY_TYPE_SM2 )
    {
        if( strHash != "SM3" )
        {
            QString strMsg = tr("SM2 Key have to use SM3 hash for verifing. do you change hash as SM3?");
            bool bVal = berApplet->yesOrNoBox( strMsg, this, true );

            if( bVal == true )
            {
                strHash = "SM3";
                mHashTypeCombo->setCurrentText( strHash );
            }
        }
    }

    *pnType = nType;
    ret = JSR_OK;

end :
    JS_BIN_reset( &binCert );

    return ret;
}

void SignVerifyDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void SignVerifyDlg::updateStatusLabel()
{
    mStatusLabel->setText( QString( "Init|Update X %1").arg( update_cnt_));
}

void SignVerifyDlg::checkPubKeyVerify()
{
    bool bVal = mPubKeyVerifyCheck->isChecked();

    if( bVal )
    {
        mCertLabel->setText( tr("PublicKey" ) );
        mCertGroup->setTitle( tr("Private key and Public key" ));
        mCertViewBtn->setEnabled(false);
    }
    else
    {
        mCertLabel->setText( tr("Certificate") );
        mCertGroup->setTitle( tr( "Private key and Certificate" ));
        mCertViewBtn->setEnabled(true);
    }
}

void SignVerifyDlg::checkAutoCertOrPubKey()
{
    bool bVal = mAutoCertPubKeyCheck->isChecked();

    mPubKeyVerifyCheck->setEnabled( !bVal );
}

void SignVerifyDlg::clickCheckKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binCert = {0,0};

    QString strCertPath = mCertPath->text();

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) return;

    if( strCertPath.length() < 1 )
    {
        berApplet->elog( "Select a certificate" );
        return;
    }

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( mAutoCertPubKeyCheck->isChecked() )
    {
        if( JS_PKI_isCert( &binCert ) == 0 )
            mPubKeyVerifyCheck->setChecked( true );
        else
            mPubKeyVerifyCheck->setChecked( false );
    }

    if( mPubKeyVerifyCheck->isChecked() )
    {
        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binPub );
    }
    else
    {
        ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
        if( ret != 0 ) goto end;
    }

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );

    if( ret == JSR_VALID )
        berApplet->messageBox( tr("The keypair is correct"), this );
    else
        berApplet->warningBox( QString( tr("The keypair is incorrect [%1]").arg(ret)), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
}

void SignVerifyDlg::findPrivateKey()
{
    QString strPath = mPriKeyPath->text();
    strPath = berApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);

    update();
}

void SignVerifyDlg::findCert()
{
    QString strPath = mCertPath->text();
    strPath = berApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText( fileName );

    update();
}

void SignVerifyDlg::algChanged(int index)
{
    QString strAlg = mAlgTypeCombo->currentText();

    if( mUseKeyAlgCheck->isChecked() == false )
    {
        if( strAlg == "RSA" )
        {
            mVersionCombo->setEnabled(true);
            mVersionLabel->setEnabled(true);
        }
        else
        {
            mVersionCombo->setEnabled( false );
            mVersionLabel->setEnabled( false );
        }
    }
    else
    {
        mVersionCombo->setEnabled(true);
    }

    if( strAlg == "SM2" )
    {
        mHashTypeCombo->setCurrentText( "SM3" );
    }
    else
    {
        mHashTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
    }

    if( strAlg == "Ed25519" || strAlg == "Ed448" )
    {
        mDigestBtn->setEnabled(false);
        mHashTypeCombo->setDisabled(true);
    }
    else
    {
        mDigestBtn->setEnabled(true);
        mHashTypeCombo->setDisabled(false);
    }
}

int SignVerifyDlg::signVerifyInit()
{
    int ret = 0;
    int nType = 0;
    BIN binPri = {0,0};
    BIN binPubKey = {0,0};
    QString strHash;

    update_cnt_ = 0;

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    if( mSignRadio->isChecked() )
    {
        ret = getPrivateKey( &binPri, &nType );
        if( ret != CKR_OK ) goto end;
    }
    else
    {
        ret = getPublicKey( &binPubKey, &nType );
        if( ret != CKR_OK ) goto end;
    }

    if( nType == JS_PKI_KEY_TYPE_ED25519 || nType == JS_PKI_KEY_TYPE_ED448 )
    {
        berApplet->warningBox(tr( "EdDSA does not support this feature."), this );
        ret = JSR_UNSUPPORTED_ALGORITHM;
        goto end;
    }

    strHash = mHashTypeCombo->currentText();

    if( mSignRadio->isChecked() )
    {
        mOutputText->clear();
        ret = JS_PKI_signInit( &sctx_, strHash.toStdString().c_str(), nType, &binPri );

        if( ret == 0 )
        {
            berApplet->log( "-- Make signature init" );
            berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));

            if( nType != JS_PKI_KEY_TYPE_ED25519 && nType != JS_PKI_KEY_TYPE_ED448 )
                berApplet->log( QString( "Hash             : %1" ).arg( strHash ));

            berApplet->log( QString( "Init Private Key : %1" ).arg( getHexString( &binPri )));
        }
    }
    else
    {
        ret = JS_PKI_verifyInit( &sctx_, strHash.toStdString().c_str(), nType, &binPubKey );

        if( ret == 0 )
        {
            berApplet->log( "-- Verify signature init" );
            berApplet->log( QString( "Algorithm       : %1" ).arg( mAlgTypeCombo->currentText() ));

            if( nType != JS_PKI_KEY_TYPE_ED25519 && nType != JS_PKI_KEY_TYPE_ED448 )
                berApplet->log( QString( "Hash            : %1" ).arg( strHash ));

            berApplet->log( QString( "Init Public Key : %1" ).arg(getHexString(&binPubKey)));
        }
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Initialization successful" );
    }
    else
    {
        QString strFail = QString("Initialization failed [%1]").arg(ret);
        mStatusLabel->setText( strFail );
        berApplet->elog( strFail );
    }

    update();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPubKey );
    return ret;
}

void SignVerifyDlg::signVerifyUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    int nDataType = DATA_HEX;
    QString strInput = mInputText->toPlainText();

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;

    getBINFromString( &binSrc, nDataType, strInput );

    if( mSignRadio->isChecked() )
    {
        ret = JS_PKI_signUpdate( sctx_, &binSrc );

        if( ret == 0 )
        {
            berApplet->log( "-- sign update" );
            berApplet->log( QString("input : %1").arg( getHexString(&binSrc)));
        }
    }
    else
    {
        ret = JS_PKI_verifyUpdate( sctx_, &binSrc );

        if( ret == 0 )
        {
            berApplet->log( "-- verify update" );
            berApplet->log( QString("input : %1").arg( getHexString(&binSrc)));
        }
    }


    if( ret == 0 )
    {
        update_cnt_++;
        updateStatusLabel();
    }
    else
    {
        QString strFail = QString("Update failure [%1]").arg( ret);
        mStatusLabel->setText( strFail );
        berApplet->elog( strFail );
    }

    update();
    JS_BIN_reset( &binSrc );
}

void SignVerifyDlg::signVerifyFinal()
{
    int ret = 0;
    BIN binSign = {0,0};

    if( mSignRadio->isChecked() )
    {
        ret = JS_PKI_signFinal( sctx_, &binSign );

        if( ret == 0 )
        {
            char *pHex = NULL;
            JS_BIN_encodeHex( &binSign, &pHex );
            mOutputText->setPlainText( pHex );
            JS_free( pHex );
        }

        if( ret == 0 )
        {
            berApplet->log( "-- sign final" );
            berApplet->log( QString( "Signature : %1" ).arg( getHexString(&binSign)));
        }

        if( ret == 0 )
        {
            appendStatusLabel( "|Final OK" );
        }
        else
        {
            QString strFail = QString("|Final failure [%1]").arg(ret);
            appendStatusLabel( strFail );
            berApplet->elog( strFail );
        }
    }
    else
    {
        QString strOut = mOutputText->toPlainText();
        JS_BIN_decodeHex( strOut.toStdString().c_str(), &binSign );

        ret = JS_PKI_verifyFinal( sctx_, &binSign );

        if( ret == JSR_VERIFY )
            berApplet->messageBox( tr("Verification successful"), this );
        else {
            berApplet->warningBox( tr("Verification failed [%1]").arg(ret), this );
        }

        if( ret == JSR_VERIFY )
        {
            appendStatusLabel( "|Final OK" );
        }
        else
        {
            QString strFail = QString("Final failure [%1]").arg(ret);
            mStatusLabel->setText( strFail );
            berApplet->elog( strFail );
        }
    }


end :
    JS_BIN_reset( &binSign );

    if( sctx_ ) JS_PKI_signFree( &sctx_ );


    update();
}

void SignVerifyDlg::Run()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        dataRun();
    else
    {
        if( mRunThreadCheck->isChecked() )
            fileRunThread();
        else
            fileRun();
    }
}

void SignVerifyDlg::dataRun()
{
    int ret = 0;
    int nType = -1;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binPubKey = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;

    int nDataType = DATA_HEX;
    QString strAlg;
    QString strHash;
    QString strInput = mInputText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputHexRadio->isChecked() )
        nDataType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;

    getBINFromString( &binSrc, nDataType, strInput );

    if( mVersionCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    if( mSignRadio->isChecked() )
    {
        ret = getPrivateKey( &binPri, &nType );
        if( ret != CKR_OK ) goto end;
    }
    else
    {
        ret = getPublicKey( &binPubKey, &nType );
        if( ret != CKR_OK ) goto end;
    }

    strHash = mHashTypeCombo->currentText();
    strAlg = mAlgTypeCombo->currentText();

    if( mSignRadio->isChecked() )
    {
        if( strAlg == "RSA" )
        {
            ret = JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), nVersion, &binSrc, &binPri, &binOut );
        }
        else if( strAlg == "SM2" || strAlg == "ECDSA" )
        {
            ret = JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        }
        else if( strAlg == "DSA" )
        {
            ret = JS_PKI_DSA_Sign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        }
        else if( strAlg == "Ed25519" || strAlg == "Ed448" )
        {
            int nParam = JS_PKI_KEY_TYPE_ED25519;
            if( strAlg == "Ed448" ) nParam = JS_PKI_KEY_TYPE_ED448;

            ret = JS_PKI_EdDSA_Sign( nParam, &binSrc, &binPri, &binOut );
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log("-- Make Signature" );
            berApplet->logLine();
            berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));

            if( nType != JS_PKI_KEY_TYPE_ED25519 && nType != JS_PKI_KEY_TYPE_ED448 )
                berApplet->log( QString( "Hash             : %1").arg( strHash ));

            berApplet->log( QString( "Sign Src         : %1" ).arg(getHexString(&binSrc)));
//            berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
            berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();
        }

        if( ret == 0 )
            mStatusLabel->setText( "Signature Success" );
        else
        {
            QString strFail = QString("Signature failure [%1]").arg(ret);
            mStatusLabel->setText( strFail );
            berApplet->elog( strFail );
        }
    }
    else
    {
        getBINFromString( &binOut, DATA_HEX, strOutput.toStdString().c_str() );

        if( strAlg == "RSA" )
        {
            ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binPubKey );
        }
        else if( strAlg == "ECDSA" || strAlg == "SM2" )
        {
            ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binSrc, &binOut, &binPubKey );
        }
        else if( strAlg == "DSA" )
        {
            ret = JS_PKI_DSA_Verify( strHash.toStdString().c_str(), &binSrc, &binOut, &binPubKey );
        }
        else if( strAlg == "Ed25519" || strAlg == "Ed448" )
        {
            ret = JS_PKI_EdDSA_Verify( &binSrc, &binOut, &binPubKey );
        }

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- Verify Signature" );
            berApplet->logLine();
            berApplet->log( QString( "Algorithm         : %1" ).arg( mAlgTypeCombo->currentText() ));
            berApplet->log( QString( "Verify Src        : %1" ).arg(getHexString(&binSrc)));
            berApplet->log( QString( "Verify Public Key : %1" ).arg(getHexString( &binPubKey )));
            berApplet->logLine();
        }

        if( ret == JSR_VERIFY )
        {
            mStatusLabel->setText( "Verification successful" );
        }
        else
        {
            QString strFail = QString("Verification failure [%1]").arg(ret);
            mStatusLabel->setText( strFail );
            berApplet->elog( strFail );
        }

        if( ret == JSR_VERIFY )
            berApplet->messageBox( tr("Verification successful"), this );
        else {
            berApplet->warningBox( tr("Verification failure"), this );
        }
    }

    update();
end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPubKey );

    if( pOut ) JS_free( pOut );
}

void SignVerifyDlg::fileRun()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};


    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("You have to find src file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mSignProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    if( signVerifyInit() != 0 )
    {
        berApplet->elog( "fail to init" );
        return;
    }

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );
    if( fp == NULL )
    {
        berApplet->elog( QString( "failed to read file:%1").arg( strSrcFile ));
        goto end;
    }

    berApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));


    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            berApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        if( mSignRadio->isChecked() )
        {
            ret = JS_PKI_signUpdate( sctx_, &binPart );
        }
        else
        {
            ret = JS_PKI_verifyUpdate( sctx_, &binPart );
        }

        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update [%1]").arg(ret));
            break;
        }

        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mSignProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mSignProgBar->setValue( 100 );

        if( ret == 0 )
        {
            QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
            appendStatusLabel( strStatus );

            signVerifyFinal();
        }
    }

end :
    JS_BIN_reset( &binPart );
}

void SignVerifyDlg::digestRun()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;
    int nAlgType = 0;

    int nDataType = DATA_STRING;
    int nDigestLen = 0;

    QString strHash = mHashTypeCombo->currentText();
    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Enter your data"), this );
        return;
    }

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputHexRadio->isChecked() )
    {
        nDataType = DATA_HEX;
    }
    else if( mInputBase64Radio->isChecked() )
    {
        nDataType = DATA_BASE64;
    }

    nDigestLen = getDigestLength( strHash );
    getBINFromString( &binSrc, nDataType, strInput );

    if( binSrc.nLen != nDigestLen )
    {
        bool bVal = berApplet->yesOrNoBox(
            tr( "The input length(%1) and digest length(%2) do not match. Do you want to continue?").arg( binSrc.nLen ).arg( nDigestLen), this, true );

        if( bVal == false ) goto end;
    }

    berApplet->log( QString( "Algorithm : %1 Hash %2").arg( mAlgTypeCombo->currentText()).arg( strHash ));

    if( mSignRadio->isChecked() )
    {
        if( mCertGroup->isChecked() == true )
        {
            ret = readPrivateKey( &binPri );
            if( ret != 0 ) goto end;
        }
        else
        {
            CertManDlg certMan;
            QString strPriHex;
            certMan.setMode(ManModeSelBoth );
            certMan.setTitle( tr( "Select a sign certificate") );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            strPriHex = certMan.getPriKeyHex();
            JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binPri );
        }

        if( mUseKeyAlgCheck->isChecked() )
        {
            nAlgType = JS_PKI_getPriKeyType( &binPri );
            berApplet->log( QString( "PriKey Type : %1").arg( getKeyTypeName( nAlgType )));

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
            else if( nAlgType == JS_PKI_KEY_TYPE_DSA )
                mAlgTypeCombo->setCurrentText( "DSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ED25519 )
                mAlgTypeCombo->setCurrentText( "Ed25519" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ED448 )
                mAlgTypeCombo->setCurrentText( "Ed448" );
        }

        QString strAlg = mAlgTypeCombo->currentText();

        if( strAlg == "RSA" )
            nAlgType = JS_PKI_KEY_TYPE_RSA;
        else if( strAlg == "ECDSA" )
            nAlgType = JS_PKI_KEY_TYPE_ECC;
        else if( strAlg == "SM2" )
            nAlgType = JS_PKI_KEY_TYPE_SM2;
        else if( strAlg == "DSA" )
            nAlgType = JS_PKI_KEY_TYPE_DSA;
        else if( strAlg == "Ed25519" || strAlg == "Ed448" )
        {
            nAlgType = JS_PKI_KEY_TYPE_ED25519;

            if( strAlg == "Ed448" ) nAlgType = JS_PKI_KEY_TYPE_ED448;
        }

        ret = JS_PKI_SignDigest( nAlgType, strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        mOutputText->setPlainText( getHexString( &binOut ));

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Sign Digest Src  : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
        berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));

        if( ret == 0 )
            mStatusLabel->setText( "SignDigest successful" );
        else
            mStatusLabel->setText( QString("SignDigest failure [%1]").arg(ret));
    }
    else
    {
        if( mCertGroup->isChecked() == true )
        {
            if( mCertPath->text().isEmpty() )
            {
                berApplet->warningBox( tr( "Select a certificate"), this );
                goto end;
            }

            JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
        }
        else
        {
            CertManDlg certMan;
            QString strCertHex;

            certMan.setMode(ManModeSelCert);
            certMan.setTitle( tr( "Select a sign certificate") );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            strCertHex = certMan.getCertHex();
            JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binCert );
        }

        JS_BIN_decodeHex( mOutputText->toPlainText().toStdString().c_str(), &binOut );

        if( mAutoCertPubKeyCheck->isChecked() )
        {
            if( JS_PKI_isCert( &binCert ) == 0 )
            {
                mPubKeyVerifyCheck->setChecked(true);
                JS_BIN_copy( &binPubKey, &binCert );
            }
            else
            {
                mPubKeyVerifyCheck->setChecked(false);
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            }
        }
        else
        {
            if( mPubKeyVerifyCheck->isChecked() == false )
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            else
                JS_BIN_copy( &binPubKey, &binCert );
        }

        if( mUseKeyAlgCheck->isChecked() )
        {
            int id = JS_PKI_getPubKeyType( &binPubKey );
            berApplet->log( QString( "PubKey Type : %1").arg( getKeyTypeName( id )));

            if( id == JS_PKI_KEY_TYPE_RSA )
                mAlgTypeCombo->setCurrentText( "RSA" );
            else if( id == JS_PKI_KEY_TYPE_SM2 )
                mAlgTypeCombo->setCurrentText( "SM2" );
            else if( id == JS_PKI_KEY_TYPE_ECC )
                mAlgTypeCombo->setCurrentText( "ECDSA" );
            else if( id == JS_PKI_KEY_TYPE_DSA )
                mAlgTypeCombo->setCurrentText( "DSA" );
            else if( id == JS_PKI_KEY_TYPE_ED25519 )
                mAlgTypeCombo->setCurrentText( "Ed25519" );
            else if( id == JS_PKI_KEY_TYPE_ED448 )
                mAlgTypeCombo->setCurrentText( "Ed448" );
        }


        QString strAlg = mAlgTypeCombo->currentText();

        if( strAlg == "RSA" )
            nAlgType = JS_PKI_KEY_TYPE_RSA;
        else if( strAlg == "ECDSA" )
            nAlgType = JS_PKI_KEY_TYPE_ECC;
        else if( strAlg == "SM2" )
            nAlgType = JS_PKI_KEY_TYPE_SM2;
        else if( strAlg == "DSA" )
            nAlgType = JS_PKI_KEY_TYPE_DSA;
        else if( strAlg == "Ed25519" || strAlg == "Ed448" )
        {
            nAlgType = JS_PKI_KEY_TYPE_ED25519;

            if( strAlg == "Ed448" ) nAlgType = JS_PKI_KEY_TYPE_ED448;
        }

        ret = JS_PKI_VerifyDigest( nAlgType, strHash.toStdString().c_str(), &binSrc, &binPubKey, &binOut );

        berApplet->log( QString( "Algorithm         : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Verify Digest Src : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Verify Public Key : %1" ).arg(getHexString( &binPubKey )));

        if( ret == JSR_VERIFY )
        {
            mStatusLabel->setText( "VerifyDigest successful" );
        }
        else
            mStatusLabel->setText( QString("VerifyDigest failure [%1]").arg(ret) );

        if( ret == JSR_VERIFY )
            berApplet->messageBox( tr("VerifyDigest successful"), this );
        else {
            berApplet->warningBox( tr("VerifyDigest failure"), this );
        }
    }

    update();
end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPubKey );

    if( pOut ) JS_free( pOut );
}

void SignVerifyDlg::inputChanged()
{
    int nType = DATA_STRING;
    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void SignVerifyDlg::outputChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void SignVerifyDlg::clickSign()
{
    mRunBtn->setText( tr( "Sign" ));
    mDigestBtn->setText( tr( "SignDigest" ));

    if( mCertGroup->isChecked() == true )
    {
        mPriKeyPath->setEnabled( true );
        mCertPath->setEnabled(false);
    }
    else
    {
        mPriKeyPath->setEnabled( false );
        mCertPath->setEnabled(false);
    }
}

void SignVerifyDlg::clickVerify()
{
    mRunBtn->setText( tr( "Verify"));
    mDigestBtn->setText( tr( "VerifyDigest" ));

    if( mCertGroup->isChecked() == true )
    {
        mPriKeyPath->setEnabled( false );
        mCertPath->setEnabled( true );
    }
    else
    {
        mPriKeyPath->setEnabled( false );
        mCertPath->setEnabled(false);
    }
}

void SignVerifyDlg::clickInputClear()
{
    mInputText->clear();
}

void SignVerifyDlg::clickOutputClear()
{
    mOutputText->clear();
}

void SignVerifyDlg::clickPriKeyView()
{
    BIN binPri = {0,0};
    int nType = -1;

    PriKeyInfoDlg priKeyInfo;

    int ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void SignVerifyDlg::clickPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mPriKeyPath->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        mPriKeyPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mPriKeyPath->setFocus();
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SignVerifyDlg::clickCertView()
{
    BIN binCert = {0,0};

    QString strPath = mCertPath->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a certificate"), this );
        mCertPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( JS_PKI_isCert( &binCert ) != 1 )
    {
        berApplet->warningBox( tr( "It is not a certificate"), this );
        mCertPath->setFocus();
        JS_BIN_reset( &binCert );
        return;
    }

    JS_BIN_reset( &binCert );

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SignVerifyDlg::clickCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mCertPath->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a certificate"), this );
        mCertPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SignVerifyDlg::clickPriKeyType()
{
    BIN binPri = {0,0};
    int nType = -1;
    int ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private Key Type is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void SignVerifyDlg::clickCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    QString strKind;
    int nType = -1;

    QString strPath = mCertPath->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select certificate or public key"), this );
        mCertPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( JS_PKI_isCert( &binCert ) )
    {
        JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
        strKind = tr("Certificate");
    }
    else
    {
        JS_BIN_copy( &binPubKey, &binCert );
        strKind = tr( "Public Key" );
    }

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "%1 Type is %2").arg( strKind).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void SignVerifyDlg::checkUseKeyAlg()
{
    bool bVal = mUseKeyAlgCheck->isChecked();

    mAlgTypeCombo->setEnabled( !bVal );
}

void SignVerifyDlg::clickClearDataAll()
{
    mInputText->clear();
    mPriKeyPath->clear();
    mCertPath->clear();
    mOutputText->clear();
    mStatusLabel->clear();
    mPasswdText->clear();

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();
    mFileTotalSizeText->clear();
    mFileReadSizeText->clear();
    mSignProgBar->setValue(0);
}

void SignVerifyDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();
    strPath = berApplet->curFilePath( strPath );

    QString strSrcFile = findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strSrcFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strSrcFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strSrcFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mSignProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void SignVerifyDlg::changeInputTab( int index )
{
    if( index == 0 )
        mDigestBtn->setEnabled(true);
    else
        mDigestBtn->setEnabled(false);
}

void SignVerifyDlg::checkEncPriKey()
{
    bool bVal = mEncPrikeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void SignVerifyDlg::fileRunThread()
{
    if( signVerifyInit() != 0 )
    {
        berApplet->elog( "fail to init" );
        return;
    }

    startTask();
}

void SignVerifyDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new SignVerifyThread;
    QString strSrcFile = mSrcFileText->text();

    if( strSrcFile.length() < 1)
    {
        berApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect( thread_, &SignVerifyThread::taskFinished, this, &SignVerifyDlg::onTaskFinished);
    connect( thread_, &SignVerifyThread::taskUpdate, this, &SignVerifyDlg::onTaskUpdate);

    thread_->setSignCTX( sctx_ );
    thread_->setVeify( mSignRadio->isChecked() ? false : true );
    thread_->setSrcFile( strSrcFile );
    thread_->start();

    berApplet->log("Task is running...");
}

void SignVerifyDlg::onTaskFinished()
{
    berApplet->log("Task finished");

    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    signVerifyFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void SignVerifyDlg::onTaskUpdate( int nUpdate )
{
    berApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mSignProgBar->setValue( nPercent );
}

void SignVerifyDlg::checkCertGroup()
{
    if( mCertGroup->isChecked() == true )
    {
        if( mSignRadio->isChecked() == true )
            clickSign();
        else
            clickVerify();
    }
}
