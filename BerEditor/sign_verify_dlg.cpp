/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QFileInfo>
#include <QDateTime>
#include <QButtonGroup>
#include <QElapsedTimer>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "sign_verify_dlg.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_raw.h"
#include "js_error.h"
#include "common.h"
#include "sign_verify_thread.h"
#include "pri_key_info_dlg.h"
#include "key_pair_man_dlg.h"
#include "js_pqc.h"


static QStringList versionTypes = {
    "V15",
    "PSS"
};

static bool _isUseHash( int nKeyAlg )
{
    switch ( nKeyAlg ) {
    case JS_PKI_KEY_TYPE_RSA :
    case JS_PKI_KEY_TYPE_DSA :
    case JS_PKI_KEY_TYPE_ECDSA :
    case JS_PKI_KEY_TYPE_SM2 :
        return true;
    default:
        return false;
    }

    return false;
}

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    sctx_ = NULL;
    thread_ = NULL;

    setupUi(this);
    initUI();
    setAcceptDrops( true );

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));

    connect( mSignRadio, SIGNAL(clicked()), this, SLOT(checkSign()));
    connect( mVerifyRadio, SIGNAL(clicked()), this, SLOT(checkVerify()));

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(signVerifyInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(signVerifyUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(signVerifyFinal()));
    connect( mResetBtn, SIGNAL(clicked()), this, SLOT(clickReset()));

    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));

    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyView()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

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


    initialize();
    mRunBtn->setDefault(true);
    mInputText->setFocus();


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

    mInputClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SignVerifyDlg::~SignVerifyDlg()
{
    if( sctx_ ) JS_PKI_signFree( &sctx_ );
    if( thread_ ) delete thread_;
}

void SignVerifyDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void SignVerifyDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            mInputTab->setCurrentIndex(1);
            setSrcFileInfo( url.toLocalFile() );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void SignVerifyDlg::initUI()
{
    mInputTypeCombo->addItems( kDataTypeList );
    mHashTypeCombo->addItem("");
    mHashTypeCombo->addItems(kHashList);
    mHashTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
    mHashTypeCombo->setToolTip( tr("This combo is for RSA, ECDSA, and DSA") );

    mVersionCombo->addItems(versionTypes);
    mRunThreadCheck->setChecked(true);

    mOutputText->setPlaceholderText( tr("Hex value" ) );

    mPriKeyPath->setPlaceholderText( tr("Select a private key") );
    mCertPath->setPlaceholderText( tr( "Select a certificate" ));
    mSrcFileText->setPlaceholderText( tr( "Find the target file" ));
}

void SignVerifyDlg::initialize()
{
    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mSignRadio );
    runGroup->addButton( mVerifyRadio );

    mInputTab->setCurrentIndex(0);

    checkEncPriKey();
    mSignRadio->click();
    mUseCertManCheck->setChecked( berApplet->settingsMgr()->useCertMan() );
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
        if( mUseCertManCheck->isChecked() == true )
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

    nType = JS_PKI_getPriKeyType( pPriKey );
    berApplet->log( QString( "PriKey Type : %1").arg( JS_PKI_getKeyAlgName( nType )));

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
            berApplet->warningBox( tr( "Select a certificate or public key"), this );
            mCertPath->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "failed to read a certificate or public key: %1").arg( ret ), this );
            mPriKeyPath->setFocus();
            return  -1;
        }

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
        if( mUseCertManCheck->isChecked() == true )
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

    nType = JS_PKI_getPubKeyType( pPubKey );
    berApplet->log( QString( "PubKey Type : %1").arg( JS_PKI_getKeyAlgName( nType )));

    *pnType = nType;
    ret = JSR_OK;

end :
    JS_BIN_reset( &binCert );

    return ret;
}

void SignVerifyDlg::findPrivateKey()
{
    QString strPath = mPriKeyPath->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);

    update();
}

void SignVerifyDlg::findCert()
{
    QString strPath = mCertPath->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText( fileName );

    update();
}

int SignVerifyDlg::signVerifyInit()
{
    int ret = 0;
    int nType = 0;
    BIN binPri = {0,0};
    BIN binPubKey = {0,0};
    QString strHash = mHashTypeCombo->currentText();
    QString strAlg;

    clickReset();

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

    strAlg = JS_PKI_getKeyAlgName( nType );

    if( _isUseHash( nType ) == false )
    {
        QString strMode = mRunBtn->text();
        berApplet->warningBox(tr( "%1 does not support this feature[Init-Update-Final]\nUse %2")
                                  .arg( strAlg ).arg( strMode ), this );
        ret = JSR_UNSUPPORTED_ALGORITHM;
        goto end;
    }

    if( nType == JS_PKI_KEY_TYPE_SM2 )
    {
        if( strHash != "SM3" )
        {
            bool bVal = berApplet->yesOrNoBox( tr("SM2 must use SM3 hash. Would you like to change the hash to SM3?"), this );
            if( bVal == false ) goto end;

            mHashTypeCombo->setCurrentText( "SM3" );
        }
    }

    strHash = mHashTypeCombo->currentText();
    if( strHash.length() < 1 )
    {
        berApplet->warningBox( tr( "Please specify a hash" ), this );
        mHashTypeCombo->setFocus();
        goto end;
    }

    if( mSignRadio->isChecked() )
    {
        mOutputText->clear();
        ret = JS_PKI_signInit( &sctx_, strHash.toStdString().c_str(), nType, &binPri );


        if( ret == 0 )
        {
            berApplet->log( "-- Make signature init" );
            berApplet->log( QString( "Algorithm        : %1" ).arg( strAlg ));
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
            berApplet->log( QString( "Algorithm       : %1" ).arg( strAlg ));
            berApplet->log( QString( "Hash            : %1" ).arg( strHash ));
            berApplet->log( QString( "Init Public Key : %1" ).arg(getHexString(&binPubKey)));
        }
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
        mInitText->setText( "OK" );
    }
    else
    {
        QString strFail = QString("Initialization failed [%1]").arg(ret);
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mInitText->setText( QString("%1").arg(ret));
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

    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();

    ret = getBINFromString( &binSrc, strType, strInput );
    FORMAT_WARN_GO(ret);

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
        int nUpdate = mUpdateText->text().toInt();
        if( nUpdate >= 0 )
        {
            nUpdate++;
            mUpdateText->setText( QString("%1").arg(nUpdate));
        }

        mStatusLabel->setText( "Update OK" );
    }
    else
    {
        QString strFail = QString("Update failure [%1]").arg( ret);
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mUpdateText->setText( QString("%1").arg(ret));
        berApplet->elog( strFail );
    }

end :
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
            mStatusLabel->setText( "Final OK" );
            mFinalText->setText( "OK" );
        }
        else
        {
            QString strFail = QString("|Final failure [%1]").arg(ret);
            mStatusLabel->setText( QString("%1").arg(JERR(ret)));
            mUpdateText->setText( QString("%1").arg(ret));
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
            mStatusLabel->setText( "Final OK" );
            mFinalText->setText( "OK" );
        }
        else
        {
            QString strFail = QString("Final failure [%1]").arg(ret);
            mStatusLabel->setText( QString("%1").arg(JERR(ret)));
            mUpdateText->setText( QString("%1").arg(ret));
            berApplet->elog( strFail );
        }
    }


end :
    JS_BIN_reset( &binSign );

    if( sctx_ ) JS_PKI_signFree( &sctx_ );
}

void SignVerifyDlg::clickReset()
{
    mStatusLabel->setText( "Status" );

    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }
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

    QString strAlg;
    QString strHash = mHashTypeCombo->currentText();
    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();
    QString strOutput = mOutputText->toPlainText();

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    ret = getBINFromString( &binSrc, strType, strInput );
    FORMAT_WARN_GO(ret);

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

    if( _isUseHash( nType ) == false  )
        mHashTypeCombo->setCurrentText( "" );
    else
    {
        if( strHash.length() < 1 )
        {
            berApplet->warningBox( tr( "Please specify a hash" ), this );
            mHashTypeCombo->setFocus();
            goto end;
        }
    }

    if( nType == JS_PKI_KEY_TYPE_SM2 )
    {
        if( strHash != "SM3" )
        {
            bool bVal = berApplet->yesOrNoBox( tr("SM2 must use SM3 hash. Would you like to change the hash to SM3?"), this );
            if( bVal == false ) goto end;

            mHashTypeCombo->setCurrentText( "SM3" );
        }
    }

    strHash = mHashTypeCombo->currentText();

    strAlg = JS_PKI_getKeyAlgName( nType );

    if( mSignRadio->isChecked() )
    {
        qint64 us = 0;
        QElapsedTimer timer;

        if( strAlg == JS_PKI_KEY_NAME_RSA )
        {
            timer.start();
            ret = JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), nVersion, &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_SM2 || strAlg == JS_PKI_KEY_NAME_ECDSA )
        {
            timer.start();
            ret = JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_DSA )
        {
            timer.start();
            ret = JS_PKI_DSA_Sign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_EDDSA )
        {
            timer.start();
            ret = JS_PKI_EdDSA_Sign( &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
        {
            timer.start();
            ret = JS_ML_DSA_sign( &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
        {
            timer.start();
            ret = JS_SLH_DSA_sign( &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( QString( "-- Compute Signature [time: %1 ms]" ).arg( getMS( us )));
            berApplet->logLine2();
            berApplet->log( QString( "Algorithm        : %1" ).arg( strAlg ));
            berApplet->log( QString( "Hash             : %1").arg( strHash ));
            berApplet->log( QString( "Sign Src         : %1" ).arg(getHexString(&binSrc)));
            berApplet->log( QString( "Sign Private Key : [hidden]" ));
            berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();
        }

        if( ret == 0 )
        {
            mStatusLabel->setText( "Signature Success" );
            berApplet->messageBox( tr("Signature value creation succeeded"), this );
        }
        else
        {
            QString strFail = QString("Signature failure [%1]").arg(ret);
            mStatusLabel->setText( strFail );
            berApplet->warningBox( tr("Failed to generate Signature value : %1").arg( JERR(ret)), this );
        }
    }
    else
    {
        qint64 us = 0;
        QElapsedTimer timer;

        ret = getBINFromString( &binOut, DATA_HEX, strOutput.toStdString().c_str() );
        FORMAT_WARN_GO(ret);

        if( strAlg == JS_PKI_KEY_NAME_RSA )
        {
            timer.start();
            ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_ECDSA || strAlg == JS_PKI_KEY_NAME_SM2 )
        {
            timer.start();
            ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_DSA )
        {
            timer.start();
            ret = JS_PKI_DSA_Verify( strHash.toStdString().c_str(), &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_EDDSA )
        {
            timer.start();
            ret = JS_PKI_EdDSA_Verify( &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
        {
            timer.start();
            ret = JS_ML_DSA_verify( &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
        {
            timer.start();
            ret = JS_SLH_DSA_verify( &binSrc, &binOut, &binPubKey );
            us = timer.nsecsElapsed() / 1000;
        }

        berApplet->logLine();
        berApplet->log( QString( "-- Verify Signature [time: %1 ms]" ).arg( getMS( us )) );
        berApplet->logLine2();
        berApplet->log( QString( "Verify            : %1").arg( ret ));
        berApplet->log( QString( "Algorithm         : %1" ).arg( strAlg ));
        berApplet->log( QString( "Verify Src        : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Verify Public Key : %1" ).arg(getHexString( &binPubKey )));
        berApplet->logLine();

        if( ret == JSR_VERIFY )
        {
            mStatusLabel->setText( "Verification successful" );
            berApplet->messageBox( tr( "Verification was successful" ), this );
        }
        else
        {
            QString strFail = QString("Verification failure [%1]").arg(ret);
            mStatusLabel->setText( strFail );
            berApplet->warningBox( tr("Verification failed : %1" ).arg( JERR(ret)), this );
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
    qint64 nReadSize = 0;
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
        int nUpdate = mUpdateText->text().toInt();

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
            mStatusLabel->setText( QString("%1").arg(JERR(ret)));
            mUpdateText->setText( QString("%1").arg(ret));
            break;
        }

        if( nUpdate >= 0 )
        {
            nUpdate++;
            mStatusLabel->setText( "Update OK" );
            mUpdateText->setText( QString("%1").arg(nUpdate));
        }

        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

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
    int nType = -1;

    int nDigestLen = 0;

    qint64 us = 0;
    QElapsedTimer timer;

    QString strHash = mHashTypeCombo->currentText();
    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Enter your data"), this );
        return;
    }

    nDigestLen = getDigestLength( strHash );
    ret = getBINFromString( &binSrc, strType, strInput );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen != nDigestLen )
    {
        bool bVal = berApplet->yesOrNoBox(
            tr( "The input length(%1) and digest length(%2) do not match. Do you want to continue?").arg( binSrc.nLen ).arg( nDigestLen), this, true );

        if( bVal == false ) goto end;
    }

    if( mSignRadio->isChecked() )
    {
        ret = getPrivateKey( &binPri, &nAlgType );
        if( ret != CKR_OK ) goto end;

        QString strAlg = JS_PKI_getKeyAlgName( nAlgType );

        if( _isUseHash( nAlgType ) == false )
        {
            berApplet->warningBox( tr( "This key algorithm (%1) is not supported" ).arg(strAlg), this );
            ret = JSR_UNSUPPORTED_ALGORITHM;
            goto end;
        }

        timer.start();
        ret = JS_PKI_SignDigest( nAlgType, strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        us = timer.nsecsElapsed() / 1000;

        if( ret == JSR_OK )
        {
            mOutputText->setPlainText( getHexString( &binOut ));

            berApplet->log( QString( "-- Sign Digest [time: %1 ms]" ).arg( getMS(us)));
            berApplet->log( QString( "Algorithm        : %1" ).arg( strAlg ));
            berApplet->log( QString( "Sign Digest Src  : %1" ).arg(getHexString(&binSrc)));
            berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
            berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));

            mStatusLabel->setText( "SignDigest successful" );
        }
        else
        {
            mStatusLabel->setText( QString("SignDigest failure [%1]").arg(JERR(ret)));
        }
    }
    else
    {
        ret = getPublicKey( &binPubKey, &nAlgType );
        if( ret != CKR_OK ) goto end;

        QString strAlg = JS_PKI_getKeyAlgName( nAlgType );

        if( nAlgType != JS_PKI_KEY_TYPE_RSA
            && nAlgType != JS_PKI_KEY_TYPE_ECDSA
            && nAlgType != JS_PKI_KEY_TYPE_SM2
            && nAlgType != JS_PKI_KEY_TYPE_DSA )
        {
            berApplet->warningBox( tr( "This key algorithm (%1) is not supported" ).arg(strAlg), this );
            ret = JSR_UNSUPPORTED_ALGORITHM;
            goto end;
        }

        timer.start();
        ret = JS_PKI_VerifyDigest( nAlgType, strHash.toStdString().c_str(), &binSrc, &binPubKey, &binOut );
        us = timer.nsecsElapsed() / 1000;

        berApplet->log( QString( "-- Verify Digest [time: %1 ms]" ).arg( getMS(us)));
        berApplet->log( QString( "Verify            : %1").arg( ret ));
        berApplet->log( QString( "Algorithm         : %1" ).arg( strAlg ));
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
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void SignVerifyDlg::outputChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void SignVerifyDlg::checkSign()
{
    mHeadLabel->setText( tr( "Asymmetric Signature" ) );

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

void SignVerifyDlg::checkVerify()
{
    mHeadLabel->setText( tr( "Asymmetric Verification" ) );

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
        berApplet->warningBox( tr("Select a certificate or public key"), this );
        mCertPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( binCert.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mCertPath->setFocus();
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

    berApplet->messageBox( tr( "Private Key Type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void SignVerifyDlg::clickCertType()
{
    BIN binCert = {0,0};

    QString strType;
    int nType = -1;

    QString strPath = mCertPath->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select certificate or public key"), this );
        mCertPath->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( binCert.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mCertPath->setFocus();
        return;
    }

    if( JS_PKI_isCert( &binCert ) == 1 )
    {
        strType = tr( "Certificate" );
        nType = JS_PKI_getCertKeyType( &binCert );
    }
    else
    {
        strType = tr( "Public key" );
        nType = JS_PKI_getPubKeyType( &binCert );
    }

    berApplet->messageBox( tr( "%1 type is %2").arg( strType ).arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binCert );
}

void SignVerifyDlg::clickClearDataAll()
{
    mInputText->clear();
    mPriKeyPath->clear();
    mCertPath->clear();
    mOutputText->clear();
    mStatusLabel->setText( tr("Status") );
    mPasswdText->clear();

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();
    mFileTotalSizeText->clear();
    mFileReadSizeText->clear();
    mSignProgBar->setValue(0);
}

void SignVerifyDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mSignProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
}

void SignVerifyDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();

    QString strSrcFile = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );
    setSrcFileInfo( strSrcFile );
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

    signVerifyFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void SignVerifyDlg::onTaskUpdate( qint64 nUpdate )
{
    int nCount = mUpdateText->text().toInt();
    if( nCount >= 0 )
    {
        nCount++;
        mUpdateText->setText( QString("%1").arg( nCount ));
    }

    berApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mSignProgBar->setValue( nPercent );
}

void SignVerifyDlg::checkCertGroup()
{
    if( mCertGroup->isChecked() == true )
    {
        if( mSignRadio->isChecked() == true )
            checkSign();
        else
            checkVerify();
    }
}
