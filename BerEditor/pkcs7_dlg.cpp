/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QButtonGroup>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "pkcs7_dlg.h"
#include "js_pki.h"
#include "js_pkcs7.h"
#include "js_error.h"

#include "mainwindow.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"
#include "cms_info_dlg.h"
#include "common.h"
#include "settings_mgr.h"
#include "export_dlg.h"
#include "data_input_dlg.h"

static const QStringList kCipherList = { "aes-128-cbc", "aes-192-cbc", "aes-256-cbc" };

PKCS7Dlg::PKCS7Dlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    setAcceptDrops( true );

    connect( mSrcClearBtn, SIGNAL(clicked()), this, SLOT(clearSrc()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clearOutput()));
    connect( mOutputUpBtn, SIGNAL(clicked()), this, SLOT(clickOutputUp()));

    connect( mEncodeRadio, SIGNAL(clicked()), this, SLOT(checkEncode()));
    connect( mDecodeRadio, SIGNAL(clicked()), this, SLOT(checkDecode()));
    connect( mAutoDetectCheck, SIGNAL(clicked()), this, SLOT(checkAutoDetect()));
    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmd()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(clickRun()));

    connect( mSrcDecodeBtn, SIGNAL(clicked()), this, SLOT(clickSrcDecode()));
    connect( mSrcTypeBtn, SIGNAL(clicked()), this, SLOT(clickSrcType()));
    connect( mOutputTypeBtn, SIGNAL(clicked()), this, SLOT(clickOutputType()));
    connect( mOutputDecodeBtn, SIGNAL(clicked()), this, SLOT(clickOutputDecode()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(clickPriFind()));
    connect( mCertFindBtn, SIGNAL(clicked()), this, SLOT(clickCertFind()));

    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcChanged()));

    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyView()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));


    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyType()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickCertType()));

    connect( mSrcViewBtn, SIGNAL(clicked()), this, SLOT(clickSrcView()));
    connect( mOutputViewBtn, SIGNAL(clicked()), this, SLOT(clickOutputView()));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));
    connect( mReadFileBtn, SIGNAL(clicked()), this, SLOT(clickReadFile()));
    connect( mExportBtn, SIGNAL(clicked()), this, SLOT(clickExport()));

    connect( mEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

    initialize();
    mSrcText->setFocus();
    mRunBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCertGroup->layout()->setSpacing(5);
    mCertGroup->layout()->setMargin(5);

    mPriKeyViewBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);
    mPriKeyDecodeBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mCertViewBtn->setFixedWidth(34);

    mSrcDecodeBtn->setFixedWidth(34);
    mOutputViewBtn->setFixedWidth(34);
    mSrcViewBtn->setFixedWidth(34);
    mSrcTypeBtn->setFixedWidth(34);
    mOutputTypeBtn->setFixedWidth(34);

    mSrcClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
    mOutputDecodeBtn->setFixedWidth(34);
#endif    

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}



PKCS7Dlg::~PKCS7Dlg()
{

}

void PKCS7Dlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void PKCS7Dlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            BIN binData = {0,0};
            int ret = 0;

            if( mDecodeRadio->isChecked() == true )
                ret = JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binData );
            else
                ret = JS_BIN_fileRead( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binData );

            if( ret <= 0 ) return;

            if( mDecodeRadio->isChecked() == true )
            {
                int nType = JS_PKCS7_getType( &binData );
                if( nType < 0 )
                {
                    berApplet->warningBox( tr( "This file is not in PKCS7 format" ), this );
                    JS_BIN_reset( &binData );
                    return;
                }
            }

            mSrcTypeCombo->setCurrentText(kDataHex);
            mSrcText->setPlainText( getHexString( &binData ));

            JS_BIN_reset( &binData );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}


void PKCS7Dlg::initUI()
{
    mSrcTypeCombo->addItems( kDataTypeList );
    mCmdCombo->addItems( kEncodeList );
    mOutputText->setPlaceholderText( tr( "Hex value") );

    mSrcTypeCombo->setCurrentText( kDataHex );
    mEncodeRadio->setChecked(true);
    mAutoDetectCheck->setChecked(true);

    mOutputCmdText->setPlaceholderText( tr("Command Name") );
    checkEncode();
    changeCmd();
}

void PKCS7Dlg::initialize()
{
    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mCipherCombo->addItems( kCipherList );

    checkEncPriKey();

    mPriKeyPathText->setPlaceholderText( tr("Select CertMan private key") );
    mCertPathText->setPlaceholderText( tr( "Select CertMan certificate" ));
}

int PKCS7Dlg::getFlags()
{
    int nFlags = 0;

    if( mFlagGroup->isEnabled() == false )
        return -1;

    if( mFlagGroup->isChecked() == false )
        return -1;

    if( mFlagNOCERTSCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOCERTS;

    if( mFlagNOSIGSCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOSIGS;

    if( mFlagNOCHAINCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOCHAIN;

    if( mFlagNOINTERNCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOINTERN;

    if( mFlagNOVERIFYCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOVERIFY;

    if( mFlagDETACHEDCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_DETACHED;

    if( mFlagBINARYCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_BINARY;

    if( mFlagNOATTRCheck->isChecked() )
        nFlags |= JS_PKCS7_FLAG_NOATTR;


    return nFlags;
}

int PKCS7Dlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPriKeyPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a private key"), this );
        mPriKeyPathText->setFocus();
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        mPriKeyPathText->setFocus();
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a password"), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Private key decryption failed [%1]").arg( ret ), this );
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

void PKCS7Dlg::checkEncode()
{
    mHeadLabel->setText( tr( "PKCS7 message encode" ) );
    mSrcLabel->setText( tr( "Source data" ));
    mOutputLabel->setText( tr( "CMS data" ) );

    mCmdCombo->clear();
    mCmdCombo->setEnabled( true );
    mCmdCombo->addItems( kEncodeList );
    mAutoDetectCheck->setEnabled(false);
    mRunBtn->setText( tr("Encode" ));

    mSrcViewBtn->setEnabled( false );
    mSrcDecodeBtn->setEnabled( false );
    mSrcTypeBtn->setEnabled( false );

    mOutputViewBtn->setEnabled( true );
    mOutputTypeBtn->setEnabled( true );
    mOutputDecodeBtn->setEnabled( true );
}

void PKCS7Dlg::checkDecode()
{
    mHeadLabel->setText( tr( "PKCS7 message decode" ) );
    mSrcLabel->setText( tr( "CMS data" ));
    mOutputLabel->setText( tr( "Source data" ) );

    mCmdCombo->clear();
    mCmdCombo->addItems( kDecodeList );
    mAutoDetectCheck->setEnabled(true);

    bool bVal = mAutoDetectCheck->isChecked();
    mCmdCombo->setEnabled(!bVal);

    mRunBtn->setText( tr("Decode"));

    mSrcViewBtn->setEnabled( true );
    mSrcDecodeBtn->setEnabled( true );
    mSrcTypeBtn->setEnabled( true );

    mOutputViewBtn->setEnabled( false );
    mOutputTypeBtn->setEnabled( false );
    mOutputDecodeBtn->setEnabled( false );
}

void PKCS7Dlg::checkAutoDetect()
{
    bool bVal = mAutoDetectCheck->isChecked();

    mCmdCombo->setEnabled(!bVal);
}

void PKCS7Dlg::clickClose()
{
    close();
}

void PKCS7Dlg::clickOutputDecode()
{
    BIN binOutput = {0,0};

    QString strOutput = mOutputText->toPlainText();
    int ret = getBINFromString( &binOutput, DATA_HEX, strOutput );
    FORMAT_WARN_GO(ret);

    berApplet->decodeTitle( &binOutput, "PKCS#7 Message" );
end :
    JS_BIN_reset( &binOutput );
}

void PKCS7Dlg::clickPriFind()
{
    QString strPath = mPriKeyPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;
    mPriKeyPathText->setText( fileName );
}

void PKCS7Dlg::clickCertFind()
{
    QString strPath = mCertPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPathText->setText( fileName );
}

void PKCS7Dlg::clickSignedData()
{
    int ret = 0;
    int nKeyType = 0;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    int nFlags = getFlags();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mCertGroup->isChecked() == true )
    {
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) return;

        QString strSignCertPath = mCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binCert );
        certMan.getPriKey( &binPri );
    }

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_DSA )
    {
        ret = JSR_INVALID_ALG;
        berApplet->warningBox( tr("This key algorithm(%1) is not supported").arg( JS_PKI_getKeyAlgName( nKeyType )), this );
        goto end;
    }

    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        goto end;
    }


    ret = JS_PKCS7_makeSignedData( &binSrc, &binPri, &binCert, nFlags, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to create SignedData [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == JSR_OK )
    {
        mOutputCmdText->setText( kCmdSignedData );
        strOutput = getHexString( &binOutput );
        mOutputText->setPlainText( strOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdSignedData ) );
        berApplet->logLine2();
        berApplet->log( QString( "Hash        : %1" ).arg( strHash ));
        berApplet->log( QString( "Src         : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Private Key : [hidden]" ));
        berApplet->log( QString( "Certificate : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 message created" ).arg( mOutputCmdText->text() ), this );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void PKCS7Dlg::clickEnvelopedData()
{
    int ret = 0;
    int nType = -1;

    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strCipher = mCipherCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    int nFlags = getFlags();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mCertGroup->isChecked() == true )
    {
        QString strKMCertPath = mCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for recipient" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a recipient certificate") );
        certMan.setKeyAlg( JS_PKI_KEY_NAME_RSA );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binCert );
    }

    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );
    if( nType != JS_PKI_KEY_TYPE_RSA )
    {
        berApplet->warningBox(tr( "This key algorithm(%1) is not supported\nOnly RSA is supported.")
                                  .arg( JS_PKI_getKeyAlgName( nType )), this );
        goto end;
    }

    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        goto end;
    }

    ret = JS_PKCS7_makeEnvelopedData( strCipher.toStdString().c_str(), &binSrc, &binCert, nFlags, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "Failed to create EnvelopedData [%1]").arg(JERR(ret)), this );
        goto end;
    }

    if( ret == 0 )
    {
        mOutputCmdText->setText( kCmdEnvelopedData );
        strOutput = getHexString( &binOutput );
        mOutputText->setPlainText( strOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdEnvelopedData ) );
        berApplet->logLine2();
        berApplet->log( QString( "Src         : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Cipher      : %1").arg( strCipher ));
        berApplet->log( QString( "Certificate : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 message created" ).arg( mOutputCmdText->text() ), this );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}


void PKCS7Dlg::clickVerifyData()
{
    int ret = 0;
    int nType = -1;
    int nCMSType = -1;

    BIN binCert = {0,0};
    BIN binCMS = {0,0};
    BIN binSrc = {0,0};
    BIN binData = {0,0};

    QString strCMS = mSrcText->toPlainText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strSrc;

    int nFlags = getFlags();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, strSrcType, strCMS.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType != JS_PKCS7_TYPE_SIGNED )
    {
        berApplet->warningBox( tr( "This message is not signed data type[Type:%1]").arg( nCMSType ), this);
        goto end;
    }

    if( mCertGroup->isChecked() == true )
    {
        QString strSignCertPath = mCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() == QDialog::Accepted )
        {
            certMan.getCert( &binCert );
        }
        else
        {
            bool bVal = berApplet->yesOrNoBox( tr("Would you like to continue without specifying a certificate?"), this, true );
            if( bVal == false ) return;
        }
    }

    if( mFlagGroup->isChecked() && (nFlags & JS_PKCS7_FLAG_DETACHED) )
    {
        DataInputDlg dataInput;
        if( dataInput.exec() == QDialog::Accepted )
            dataInput.getData( &binData );
    }

    ret = JS_PKCS7_verifySignedData(
        &binCMS,
        &binCert,
        binData.nLen > 0 ? &binData : NULL,
        nFlags,
        mCAListCheck->isChecked() ? berApplet->settingsMgr()->CACertPath().toLocal8Bit().toStdString().c_str() : NULL,
        mTrustListCheck->isChecked() ? berApplet->settingsMgr()->trustCertPath().toLocal8Bit().toStdString().c_str() : NULL,
        &binSrc );

    if( ret == JSR_VERIFY )
    {
        int nDataType = DATA_HEX;
        QString strSrc = getHexString( &binSrc );
        mOutputCmdText->setText( kCmdVerifyData );

        berApplet->log( QString("SignedData verification result: %1").arg( ret ));
        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdVerifyData ) );
        berApplet->logLine2();
        berApplet->log( QString( "CMS    : %1" ).arg( getHexString( &binCMS )));
        berApplet->log( QString( "Cert   : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Src    : %1" ).arg( strSrc));
        berApplet->logLine();

        mOutputText->setPlainText( strSrc );

        berApplet->messageBox( tr( "VerifyData Success" ), this );
    }
    else
    {
        berApplet->warnLog( tr( "fail to verify signedData: %1").arg( JERR(ret) ), this );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binData );
}

void PKCS7Dlg::clickDevelopedData()
{
    int ret = 0;
    int nType = -1;
    int nCMSType = -1;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binCMS = {0,0};

    QString strCMS = mSrcText->toPlainText();
    QString strSrcType = mSrcTypeCombo->currentText();
    int nFlags = getFlags();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, strSrcType, strCMS.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType != JS_PKCS7_TYPE_ENVELOPED )
    {
        berApplet->warningBox( tr( "This message is not enveloped data type[Type:%1]").arg( nCMSType ), this);
        goto end;
    }

    if( mCertGroup->isChecked() == true )
    {
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) return;

        QString strKMCertPath = mCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for recipient" ), this );
            mCertPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a recipient certificate") );
        certMan.setKeyAlg( JS_PKI_KEY_NAME_RSA );

        if( certMan.exec() != QDialog::Accepted )
            return;

        certMan.getCert( &binCert );
        certMan.getPriKey( &binPri );
    }


    nType = JS_PKI_getPriKeyType( &binPri );
    if( nType < 0 )
    {
        berApplet->warningBox( tr( "Invalid private key" ), this );
        goto end;
    }

    ret = JS_PKCS7_makeDevelopedData( &binCMS, &binPri, &binCert, nFlags, &binSrc );
    berApplet->log( QString( "developedData results: %1").arg(ret));

    if( ret == 0 )
    {
        int nDataType = DATA_HEX;
        QString strSrc = getHexString( &binSrc );
        mOutputCmdText->setText( kCmdDevelopedData );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdDevelopedData ) );
        berApplet->logLine2();
        berApplet->log( QString( "CMS        : %1" ).arg( getHexString( &binCMS )));
        berApplet->log( QString( "Cert       : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "PrivateKey : [hidden]" ));
        berApplet->log( QString( "Src        : %1" ).arg( strSrc ));
        berApplet->logLine();

        mOutputText->setPlainText( strSrc );

        berApplet->messageBox( tr( "DevelopedData Success" ), this );
    }
    else
    {
        berApplet->warnLog( tr( "fail to develop data: %1").arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}


void PKCS7Dlg::clickAddSigner()
{
    int ret = 0;

    int nType = -1;
    int nCMSType = -1;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binCMS = {0,0};
    BIN binOutput = {0,0};

    QString strCMS = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter CMS value" ), this );
        mOutputText->setFocus();
        return;
    }

    if( mCertGroup->isChecked() == true )
    {
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) return;

        QString strSignCertPath = mCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binCert );
        certMan.getPriKey( &binPri );
    }

    ret = getBINFromString( &binCMS, strSrcType, strCMS.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    if( binCMS.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        goto end;
    }

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType != JS_PKCS7_TYPE_SIGNED )
    {
        berApplet->warningBox( tr( "The source is not signed data[Type:%1]").arg( nCMSType ), this);
        goto end;
    }

    ret = JS_PKCS7_addSigner( &binCMS, strHash.toStdString().c_str(), &binPri, &binCert, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to add signer [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == 0 )
    {
        strOutput = getHexString( &binOutput );
        mOutputCmdText->setText( kCmdAddSigned );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdAddSigned ) );
        berApplet->logLine2();
        berApplet->log( QString( "Hash        : %1" ).arg( strHash));
        berApplet->log( QString( "CMS         : %1" ).arg( getHexString( &binCMS )));
        berApplet->log( QString( "Private Key : [hidden]" ));
        berApplet->log( QString( "Certificate : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        mOutputText->setPlainText( strOutput );

        berApplet->messageBox( tr( "Signer is added successfully"), this );
    }

end :
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void PKCS7Dlg::srcChanged()
{   
    QString strType = mSrcTypeCombo->currentText();

    QString strLen = getDataLenString( strType, mSrcText->toPlainText() );
    mSrcLenText->setText( QString("%1").arg(strLen));
}

void PKCS7Dlg::outputChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void PKCS7Dlg::clearSrc()
{
    mSrcText->clear();
}

void PKCS7Dlg::clearOutput()
{
    mOutputText->clear();
}

void PKCS7Dlg::clickPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a private key"), this );
        mPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        mPriKeyPathText->setFocus();
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void PKCS7Dlg::clickCertView()
{
    QString strPath = mCertPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mCertPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void PKCS7Dlg::clickCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        mCertPathText->setFocus();
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

void PKCS7Dlg::clickPriKeyView()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;
    PriKeyInfoDlg priKeyInfo;

    ret = readPrivateKey( &binPri );
    if( ret != 0) return;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void PKCS7Dlg::clickPriKeyType()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    ret = readPrivateKey( &binPri );
    if( ret != 0) return;
    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private key type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void PKCS7Dlg::clickCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate"), this );
        mCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate type is %1" ).arg( JS_PKI_getKeyAlgName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}


void PKCS7Dlg::clickSrcView()
{
    int ret = -1;
    BIN binCMS = {0,0};

    int nCMSType = -1;
    QString strCMS = mSrcText->toPlainText();
    QString strType = mSrcTypeCombo->currentText();

    CMSInfoDlg cmsInfo;
//    cmsInfo.setPKCS7();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter CMS value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, strType, strCMS );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType < 0 )
    {
        berApplet->warningBox( tr( "This CMS type is not supported.").arg( nCMSType ), this );
        JS_BIN_reset( &binCMS );
        return;
    }

    cmsInfo.setCMS( &binCMS );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binCMS );
}

void PKCS7Dlg::clickSrcDecode()
{
    BIN binSrc = {0,0};

    QString strSrc = mSrcText->toPlainText();
    QString strType = mSrcTypeCombo->currentText();

    int ret = getBINFromString( &binSrc, strType, strSrc );
    FORMAT_WARN_GO(ret);

    berApplet->decodeTitle( &binSrc, "PKCS#7 Message" );
end:
    JS_BIN_reset( &binSrc );
}

void PKCS7Dlg::clickSrcType()
{
    int ret = -1;
    BIN binCMS = {0,0};

    int nCMSType = -1;
    QString strCMS = mSrcText->toPlainText();
    QString strType = mSrcTypeCombo->currentText();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter CMS value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, strType, strCMS );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType < 0 )
    {
        berApplet->warningBox( tr( "This CMS type is not supported.").arg( nCMSType ), this );
        JS_BIN_reset( &binCMS );
        return;
    }

    berApplet->messageBox( tr( "This CMS type is %1" ).arg( JS_PKCS7_getTypeName( nCMSType )), this );

end :
    JS_BIN_reset( &binCMS );
}

void PKCS7Dlg::clickOutputType()
{
    int ret = -1;
    BIN binCMS = {0,0};

    int nCMSType = -1;
    QString strCMS = mOutputText->toPlainText();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter CMS value" ), this );
        mOutputText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, DATA_HEX, strCMS );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType < 0 )
    {
        berApplet->warningBox( tr( "This CMS type is not supported.").arg( nCMSType ), this );
        JS_BIN_reset( &binCMS );
        return;
    }

    berApplet->messageBox( tr( "This CMS type is %1" ).arg( JS_PKCS7_getTypeName( nCMSType )), this );

end :
    JS_BIN_reset( &binCMS );
}

void PKCS7Dlg::clickOutputView()
{
    int ret = -1;
    BIN binCMS = {0,0};

    int nCMSType = -1;
    QString strCMS = mOutputText->toPlainText();
    CMSInfoDlg cmsInfo;
//    cmsInfo.setPKCS7();

    if( strCMS.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter CMS value" ), this );
        mOutputText->setFocus();
        return;
    }

    ret = getBINFromString( &binCMS, DATA_HEX, strCMS );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binCMS );
    if( nCMSType < 0 )
    {
        berApplet->warningBox( tr( "This CMS type is not supported.").arg( nCMSType ), this );
        JS_BIN_reset( &binCMS );
        return;
    }

    cmsInfo.setCMS( &binCMS );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binCMS );
}

void PKCS7Dlg::clickClearDataAll()
{
    mSrcText->clear();
    mOutputText->clear();

    mOutputCmdText->clear();

    mPriKeyPathText->clear();
    mCertPathText->clear();
    mPasswdText->clear();
}

void PKCS7Dlg::clickReadFile()
{
    int ret = 0;
    QString strPath;

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath);

    if( strFile.length() > 0 )
    {
        BIN binData = {0,0};

        QFileInfo fileInfo( strFile );

        if( fileInfo.size() >  kFileMax )
        {
            berApplet->warningBox( tr("The file size is too large(Max:1M)"), this );
            return;
        }

        if( mDecodeRadio->isChecked() == true )
            ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
        else
            ret = JS_BIN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binData );

        if( ret <= 0 ) return;

        if( mDecodeRadio->isChecked() == true )
        {
            int nType = JS_PKCS7_getType( &binData );
            if( nType < 0 )
            {
                berApplet->warningBox( tr( "This file is not in PKCS7 format" ), this );
                JS_BIN_reset( &binData );
                return;
            }
        }

        mSrcTypeCombo->setCurrentText(kDataHex);
        mSrcText->setPlainText( getHexString( &binData ));


        JS_BIN_reset( &binData );
    }
}

void PKCS7Dlg::clickExport()
{
    int ret = 0;
    BIN binData = {0,0};
    QString strOutput = mOutputText->toPlainText();

    if( strOutput.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no data" ), this );
        mOutputText->setFocus();
        return;
    }

    ret = getBINFromString( &binData, DATA_HEX, strOutput );
    FORMAT_WARN_GO(ret);

    if( mEncodeRadio->isChecked() == true )
    {
        int nType = JS_PKCS7_getType( &binData );
        if( nType < 0 )
        {
            berApplet->warningBox( tr( "This file is not in PKCS7 format" ), this );
            goto end;
        }

        ExportDlg exportDlg;
        exportDlg.setName( "PKCS7" );
        exportDlg.setPKCS7( &binData );
        exportDlg.exec();
    }
    else
    {
        ExportDlg exportDlg;
        exportDlg.setName( "Binary" );
        exportDlg.setBIN( &binData );
        exportDlg.exec();
    }

end :
    JS_BIN_reset( &binData );
}

void PKCS7Dlg::checkEncPriKey()
{
    bool bVal = mEncPriKeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void PKCS7Dlg::clickDigest()
{
    int ret = 0;

    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }


    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        goto end;
    }

    ret = JS_PKCS7_makeDigest( &binSrc, strHash.toStdString().c_str(), &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to create digest [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == 0 )
    {
        mOutputCmdText->setText( kCmdDigest );
        mOutputText->setPlainText( strOutput );
        strOutput = getHexString( &binOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdDigest ) );
        berApplet->logLine2();
        berApplet->log( QString( "Hash        : %1" ).arg( strHash ));
        berApplet->log( QString( "Src         : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 message created" ).arg( mOutputCmdText->text() ), this );
    }



end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
}

void PKCS7Dlg::clickData()
{
    int ret = 0;

    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        goto end;
    }


    ret = JS_PKCS7_makeData( &binSrc, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to create data [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == JSR_OK )
    {
        strOutput = getHexString( &binOutput );
        mOutputCmdText->setText( kCmdData );
        mOutputText->setPlainText( strOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdData ) );
        berApplet->logLine2();
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 message created" ).arg( mOutputCmdText->text() ), this );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
}

void PKCS7Dlg::clickGetData()
{
    int ret = 0;

    int nCMSType = -1;

    BIN binSrc = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    JP7Data sData;

    memset( &sData, 0x00, sizeof(sData));

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binSrc );
    if( nCMSType != JS_PKCS7_TYPE_DATA )
    {
        berApplet->warningBox( tr( "This message is not data type[Type:%1]").arg( nCMSType ), this);
        goto end;
    }

    ret = JS_PKCS7_getData( &binSrc, &sData );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to create data [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == 0 )
    {
        mOutputCmdText->setText( kCmdGetData );
        strOutput = getHexString( &sData.binData );
        mOutputText->setPlainText( strOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdGetData ) );
        berApplet->logLine2();
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 success" ).arg( mOutputCmdText->text() ), this );
    }



end :
    JS_BIN_reset( &binSrc );
    JS_PKCS7_resetData( &sData );
}

void PKCS7Dlg::clickGetDigest()
{
    int ret = 0;
    int nCMSType = -1;

    BIN binSrc = {0,0};

    QString strInput = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();
    QString strSrcType = mSrcTypeCombo->currentText();
    QString strOutput;

    JP7DigestData sData;

    memset( &sData, 0x00, sizeof(sData));

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
    FORMAT_WARN_GO(ret);

    nCMSType = JS_PKCS7_getType( &binSrc );
    if( nCMSType != JS_PKCS7_TYPE_DIGEST )
    {
        berApplet->warningBox( tr( "This message is not digest type[Type:%1]").arg( nCMSType ), this);
        goto end;
    }

    ret = JS_PKCS7_getDigestData( &binSrc, &sData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "Failed to get digest [%1]").arg( JERR(ret) ), this );
        goto end;
    }

    if( ret == JSR_OK )
    {
        mOutputCmdText->setText( kCmdGetDigest );
        strOutput = getHexString( &sData.binContent );
        mOutputText->setPlainText( strOutput );

        berApplet->logLine();
        berApplet->log( QString( "-- PKCS7 %1 command" ).arg( kCmdGetDigest ) );
        berApplet->logLine2();
        berApplet->log( QString( "Alg         : %1" ).arg( sData.pAlg ));
        berApplet->log( QString( "Verify      : %1").arg( sData.nVerify));
        berApplet->log( QString( "Digest      : %1" ).arg( sData.pDigest ));
        berApplet->log( QString( "Output      : %1" ).arg( strOutput ));
        berApplet->logLine();

        berApplet->messageBox( tr( "%1 success" ).arg( mOutputCmdText->text() ), this );
    }



end :
    JS_BIN_reset( &binSrc );
    JS_PKCS7_resetDigestData( &sData );
}

void PKCS7Dlg::clickOutputUp()
{
    QString strOutput = mOutputText->toPlainText();

    mSrcTypeCombo->setCurrentText(kDataHex);
    mSrcText->setPlainText( strOutput );
    mOutputText->clear();
}

void PKCS7Dlg::changeCmd()
{
    QString strCmd = mCmdCombo->currentText();

    if( strCmd == kCmdSignedData || strCmd == kCmdVerifyData || strCmd == kCmdEnvelopedData || strCmd == kCmdDevelopedData )
        mFlagGroup->setEnabled( true );
    else
        mFlagGroup->setEnabled( false );

    if( strCmd == kCmdEnvelopedData || strCmd == kCmdSignedAndEnveloped )
    {
        mCipherCombo->setEnabled( true );
    }
    else
    {
        mCipherCombo->setEnabled( false );
    }

    if( strCmd == kCmdAddSigned )
    {
        mHashCombo->setEnabled( true );
    }
    else
    {
        mHashCombo->setEnabled( false );
    }

    mCertGroup->setEnabled(false);

    if( strCmd == kCmdSignedData
        || strCmd == kCmdVerifyData
        || strCmd == kCmdAddSigned
        || strCmd == kCmdEnvelopedData
        || strCmd == kCmdDevelopedData )
    {
        mCertGroup->setEnabled( true );
    }
}

void PKCS7Dlg::clickRun()
{
    int ret = 0;
    QString strCmd = mCmdCombo->currentText();

    if( mEncodeRadio->isChecked() == true )
    {
        if( strCmd == kCmdData )
        {
            clickData();
        }
        else if( strCmd == kCmdDigest )
        {
            clickDigest();
        }
        else if( strCmd == kCmdSignedData )
        {
            clickSignedData();
        }
        else if( strCmd == kCmdEnvelopedData )
        {
            clickEnvelopedData();
        }
        else if( strCmd == kCmdAddSigned )
        {
            clickAddSigner();
        }
    }
    else
    {
        if( mAutoDetectCheck->isChecked() )
        {
            int nCMSType = -1;
            BIN binSrc = {0,0};

            QString strInput = mSrcText->toPlainText();
            QString strSrcType = mSrcTypeCombo->currentText();

            if( strInput.isEmpty() )
            {
                berApplet->warningBox( tr( "Please enter input value" ), this );
                mSrcText->setFocus();
                return;
            }

            ret = getBINFromString( &binSrc, strSrcType, strInput.toStdString().c_str() );
            if( ret < 0 )
            {
                berApplet->formatWarn( ret, this );
                return;
            }

            nCMSType = JS_PKCS7_getType( &binSrc );
            JS_BIN_reset( &binSrc );

            if( nCMSType == JS_PKCS7_TYPE_DATA )
                clickGetData();
            else if( nCMSType == JS_PKCS7_TYPE_DIGEST )
                clickGetDigest();
            else if( nCMSType == JS_PKCS7_TYPE_SIGNED )
                clickVerifyData();
            else if( nCMSType == JS_PKCS7_TYPE_ENVELOPED )
                clickDevelopedData();
            else
            {
                berApplet->warningBox( tr( "not supported CMS type[%1]").arg( nCMSType ), this );
                return;
            }
        }
        else
        {
            if( strCmd == kCmdGetData )
            {
                clickGetData();
            }
            else if( strCmd == kCmdGetDigest )
            {
                clickGetDigest();
            }
            else if( strCmd == kCmdVerifyData )
            {
                clickVerifyData();
            }
            else if( strCmd == kCmdDevelopedData )
            {
            clickDevelopedData();
            }
        }
    }
}
