/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QButtonGroup>

#include "cms_dlg.h"
#include "js_pki.h"
#include "js_pkcs7.h"

#include "mainwindow.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"
#include "common.h"

CMSDlg::CMSDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    group_ = new QButtonGroup;
    last_path_ = berApplet->curFolder();

    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(clickChange()));
    connect( mSignPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(clickSignPriFind()));
    connect( mSignCertFindBtn, SIGNAL(clicked()), this, SLOT(clickSignCertFind()));
    connect( mKMPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(clickKMPriFind()));
    connect( mKMCertFindBtn, SIGNAL(clicked()), this, SLOT(clickKMCertFind()));
    connect( mSignedDataBtn, SIGNAL(clicked()), this, SLOT(clickSignedData()));
    connect( mEnvelopedDataBtn, SIGNAL(clicked()), this, SLOT(clickEnvelopedData()));
    connect( mSignAndEnvelopedBtn, SIGNAL(clicked()), this, SLOT(clickSignAndEnvloped()));
    connect( mVerifyDataBtn, SIGNAL(clicked()), this, SLOT(clickVerifyData()));
    connect( mDevelopedDataBtn, SIGNAL(clicked()), this, SLOT(clickDevelopedData()));
    connect( mDevelopedAndVerifyBtn, SIGNAL(clicked()), this, SLOT(clickDevelopedAndVerify()));

    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mSrcStringRadio, SIGNAL(clicked()), this, SLOT(srcChanged()));
    connect( mSrcHexRadio, SIGNAL(clicked()), this, SLOT(srcChanged()));
    connect( mSrcBase64Radio, SIGNAL(clicked()), this, SLOT(srcChanged()));
    connect( mOutputStringRadio, SIGNAL(clicked()), this, SLOT(outputChanged()));
    connect( mOutputHexRadio, SIGNAL(clicked()), this, SLOT(outputChanged()));
    connect( mOutputBase64Radio, SIGNAL(clicked()), this, SLOT(outputChanged()));

    connect( mSignPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickSignPriKeyView()));
    connect( mSignPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickSignPriKeyDecode()));
    connect( mSignCertViewBtn, SIGNAL(clicked()), this, SLOT(clickSignCertView()));
    connect( mSignCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickSignCertDecode()));

    connect( mKMPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickKMPriKeyView()));
    connect( mKMPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickKMPriKeyDecode()));
    connect( mKMCertViewBtn, SIGNAL(clicked()), this, SLOT(clickKMCertView()));
    connect( mKMCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickKMCertDecode()));

    connect( mSignPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickSignPriKeyType()));
    connect( mSignCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickSignCertType()));
    connect( mKMPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickKMPriKeyType()));
    connect( mKMCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickKMCertType()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));
    connect( mReadFileBtn, SIGNAL(clicked()), this, SLOT(clickReadFile()));

    connect( mSignEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkSignEncPriKey()));
    connect( mKMEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkKMEncPriKey()));

    initialize();

    mSignedDataBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mSignCertGroup->layout()->setSpacing(5);
    mKMCertGroup->layout()->setSpacing(5);

    mSignPriKeyTypeBtn->setFixedWidth(34);
    mSignPriKeyDecodeBtn->setFixedWidth(34);
    mSignCertDecodeBtn->setFixedWidth(34);
    mSignCertTypeBtn->setFixedWidth(34);
    mSignCertViewBtn->setFixedWidth(34);
    mKMPriKeyTypeBtn->setFixedWidth(34);
    mKMPriKeyDecodeBtn->setFixedWidth(34);
    mKMCertDecodeBtn->setFixedWidth(34);
    mKMCertTypeBtn->setFixedWidth(34);
    mKMCertViewBtn->setFixedWidth(34);
#endif

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}



CMSDlg::~CMSDlg()
{

}

void CMSDlg::initialize()
{
    group_->addButton( mOutputStringRadio );
    group_->addButton( mOutputHexRadio );
    group_->addButton( mOutputBase64Radio );

    mSrcStringRadio->setChecked(true);

    checkSignEncPriKey();
    checkKMEncPriKey();
}

int CMSDlg::readSignPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mSignPriKeyPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a private key for signing"), this );
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mSignEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mSignPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Private key decryption failed [%1]").arg( ret ), this );
            mSignPasswdText->setFocus();
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

int CMSDlg::readKMPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mKMPriKeyPathText->text();

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "Private key decryption failed [%1]").arg( ret ), this );
        return  -1;
    }

    if( mKMEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mKMPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Private key decryption failed [%1]").arg( ret ), this );
            mKMPasswdText->setFocus();
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

void CMSDlg::clickClose()
{
    close();
}

void CMSDlg::clickDecode()
{
    BIN binOutput = {0,0};

    QString strOutput = mOutputText->toPlainText();

    if( mOutputStringRadio->isChecked() )
        JS_BIN_set( &binOutput, (unsigned char *)strOutput.toStdString().c_str(), strOutput.length() );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_decodeHex( strOutput.toStdString().c_str(), &binOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strOutput.toStdString().c_str(), &binOutput );

    berApplet->mainWindow()->openBer( &binOutput );

    JS_BIN_reset( &binOutput );
}

void CMSDlg::clickChange()
{
    QString strSrc = mSrcText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    mSrcText->setPlainText( strOutput );
    mOutputText->clear();

    if( mOutputStringRadio->isChecked() )
        mSrcStringRadio->setChecked(true);
    else if( mOutputHexRadio->isChecked() )
        mSrcHexRadio->setChecked(true);
    else if( mOutputBase64Radio->isChecked() )
        mSrcBase64Radio->setChecked(true);
}

void CMSDlg::clickSignPriFind()
{
    QString strPath = mSignPriKeyPathText->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;
    mSignPriKeyPathText->setText( fileName );

    last_path_ = fileName;
}

void CMSDlg::clickSignCertFind()
{
    QString strPath = mSignCertPathText->text();
    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mSignCertPathText->setText( fileName );
    last_path_ = fileName;
}

void CMSDlg::clickKMPriFind()
{
    QString strPath = mKMPriKeyPathText->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mKMPriKeyPathText->setText( fileName );
    last_path_ = fileName;
}

void CMSDlg::clickKMCertFind()
{
    QString strPath = mKMCertPathText->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mKMCertPathText->setText( fileName );
    last_path_ = fileName;
}

void CMSDlg::clickSignedData()
{
    int ret = 0;
    int nType = DATA_HEX;
    char *pOutput = NULL;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mSignCertGroup->isChecked() == true )
    {
        ret = readSignPrivateKey( &binPri );
        if( ret != 0 ) return;

        QString strSignCertPath = mSignCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for signing" ), this );
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

    if( mSrcStringRadio->isChecked() )
        nType = DATA_STRING;
    else if( mSrcHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mSrcBase64Radio->isChecked() )
        nType = DATA_STRING;

    getBINFromString( &binSrc, nType, strInput.toStdString().c_str() );


    ret = JS_PKCS7_makeSignedData( "SHA256", &binSrc, &binPri, &binCert, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to create SignedData [%1]").arg( ret ), this );
        goto end;
    }

    if( ret == 0 )
    {
        berApplet->logLine();
        berApplet->log( "-- Signed Data" );
        berApplet->logLine();
        berApplet->log( QString( "Hash        : SHA256" ));
        berApplet->log( QString( "Src         : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Private Key : %1" ).arg( getHexString( &binPri )));
        berApplet->log( QString( "Certificate : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Output      : %1" ).arg( getHexString( &binOutput )));
        berApplet->logLine();
    }

    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void CMSDlg::clickEnvelopedData()
{
    int ret = 0;
    int nType = -1;
    char *pOutput = NULL;

    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mKMCertGroup->isChecked() == true )
    {
        QString strKMCertPath = mKMCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for KM" ), this );
            return;
        }

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a KM certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binCert );
    }

    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );
    if( nType != JS_PKI_KEY_TYPE_RSA )
    {
        berApplet->warningBox(tr( "It is not an RSA certificate"), this );
        goto end;
    }

    if( mSrcStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mSrcHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    ret = JS_PKCS7_makeEnvelopedData( &binSrc, &binCert, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "Failed to create EnvelopedData [%1]").arg(ret), this );
        goto end;
    }

    if( ret == 0 )
    {
        berApplet->logLine();
        berApplet->log( "-- Enveloped Data" );
        berApplet->logLine();
        berApplet->log( QString( "Src         : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Certificate : %1" ).arg( getHexString( &binCert )));
        berApplet->log( QString( "Output      : %1" ).arg( getHexString( &binOutput )));
        berApplet->logLine();
    }

    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void CMSDlg::clickSignAndEnvloped()
{
    int ret = 0;
    int nType = -1;
    char *pOutput = NULL;

    BIN binSignPri = {0,0};
    BIN binSignCert = {0,0};
    BIN binKMCert = {0,0};
    BIN binKMPubKey = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mSignCertGroup->isChecked() == true )
    {
        ret = readSignPrivateKey( &binSignPri );
        if( ret != 0 ) return;

        QString strSignCertPath = mSignCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for signing" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binSignCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a sign certificate") );

        if(certMan.exec() != QDialog::Accepted )
            return;

        certMan.getCert( &binSignCert );
        certMan.getPriKey( &binSignPri );
    }

    if( mKMCertGroup->isChecked() == true )
    {
        QString strKMCertPath = mKMCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for KM" ), this );
            return;
        }

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binKMCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a KM certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binKMCert );
    }

    JS_PKI_getPubKeyFromCert( &binKMCert, &binKMPubKey );
    nType = JS_PKI_getPubKeyType( &binKMPubKey );
    if( nType != JS_PKI_KEY_TYPE_RSA )
    {
        berApplet->warningBox( tr("It is not an RSA certificate"), this );
        goto end;
    }

    if( mSrcStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mSrcHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    nType = JS_PKI_getPriKeyType( &binSignPri );
    if( nType != JS_PKI_KEY_TYPE_RSA )
    {
        berApplet->warningBox( tr( "It is not a private key for RSA." ), this );
        goto end;
    }

    ret = JS_PKCS7_makeSignedAndEnveloped( &binSrc, &binSignCert, &binSignPri, &binKMCert, &binOutput );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Signed And Enveloped data creation failed [%1]").arg(ret), this );
        goto end;
    }

    if( ret == 0 )
    {
        berApplet->logLine();
        berApplet->log( "-- SignedAndEnveloped Data" );
        berApplet->logLine();
        berApplet->log( QString( "Src             : %1" ).arg( getHexString( &binSrc )));
        berApplet->log( QString( "Sign Cert       : %1" ).arg( getHexString( &binSignCert )));
        berApplet->log( QString( "Sign PrivateKey : %1" ).arg( getHexString( &binSignPri )));
        berApplet->log( QString( "KM Cert         : %1" ).arg( getHexString( &binKMCert )));
        berApplet->log( QString( "Output          : %1" ).arg( getHexString( &binOutput )));
        berApplet->logLine();
    }

    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binSignPri );
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binKMCert );
    JS_BIN_reset( &binKMPubKey );
}

void CMSDlg::clickVerifyData()
{
    int ret = 0;
    int nType = -1;
    char *pOutput = NULL;

    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mSignCertGroup->isChecked() == true )
    {
        QString strSignCertPath = mSignCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for signing" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
            return;

        certMan.getCert( &binCert );
    }

    if( mSrcStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mSrcHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    ret = JS_PKCS7_verifySignedData( &binSrc, &binCert, &binOutput );
    berApplet->log( QString("SignedData verification result: %1").arg( ret ));
    berApplet->logLine();
    berApplet->log( "-- Verify Data" );
    berApplet->logLine();
    berApplet->log( QString( "Src    : %1" ).arg( getHexString( &binSrc )));
    berApplet->log( QString( "Cert   : %1" ).arg( getHexString( &binCert )));
    berApplet->log( QString( "Output : %1" ).arg( getHexString( &binOutput )));
    berApplet->logLine();


    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binCert );
}

void CMSDlg::clickDevelopedData()
{
    int ret = 0;
    int nType = -1;
    char *pOutput = NULL;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mKMCertGroup->isChecked() == true )
    {
        ret = readKMPrivateKey( &binPri );
        if( ret != 0 ) return;

        QString strKMCertPath = mKMCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for KM" ), this );
            return;
        }

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a KM certificate") );

        if( certMan.exec() != QDialog::Accepted )
            return;

        certMan.getCert( &binCert );
        certMan.getPriKey( &binPri );
    }

    if( mSrcStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mSrcHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    nType = JS_PKI_getPriKeyType( &binPri );
    if( nType < 0 )
    {
        berApplet->warningBox( tr( "Invalid private key" ), this );
        goto end;
    }

    ret = JS_PKCS7_makeDevelopedData( &binSrc, &binPri, &binCert, &binOutput );
    berApplet->log( QString( "developedData results: %1").arg(ret));

    berApplet->logLine();
    berApplet->log( "-- Verify Data" );
    berApplet->logLine();
    berApplet->log( QString( "Src        : %1" ).arg( getHexString( &binSrc )));
    berApplet->log( QString( "Cert       : %1" ).arg( getHexString( &binCert )));
    berApplet->log( QString( "PrivateKey : %1" ).arg( getHexString( &binPri )));
    berApplet->log( QString( "Output     : %1" ).arg( getHexString( &binOutput )));
    berApplet->logLine();

    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void CMSDlg::clickDevelopedAndVerify()
{
    int ret = 0;
    int nType = -1;
    char *pOutput = NULL;

    BIN binSignCert = {0,0};
    BIN binKMPri = {0,0};
    BIN binKMCert = {0,0};
    BIN binSrc = {0,0};
    BIN binOutput = {0,0};

    QString strInput = mSrcText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter input value" ), this );
        mSrcText->setFocus();
        return;
    }

    if( mSignCertGroup->isChecked() == true )
    {
        QString strSignCertPath = mSignCertPathText->text();
        if( strSignCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for signing" ), this );
            return;
        }

        JS_BIN_fileReadBER( strSignCertPath.toLocal8Bit().toStdString().c_str(), &binSignCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a sign certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert(&binSignCert);
    }

    if( mKMCertGroup->isChecked() == true )
    {
        QString strKMCertPath = mSignCertPathText->text();
        if( strKMCertPath.isEmpty() )
        {
            berApplet->warningBox(tr("Select a certificate for KM" ), this );
            goto end;
        }

        ret = readKMPrivateKey( &binKMPri );
        if( ret != 0 ) return;

        JS_BIN_fileReadBER( strKMCertPath.toLocal8Bit().toStdString().c_str(), &binKMCert );
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelBoth);
        certMan.setTitle( tr( "Select a KM certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getCert( &binKMCert );
        certMan.getPriKey( &binKMPri );
    }

    if( mSrcStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mSrcHexRadio->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Radio->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    nType = JS_PKI_getPriKeyType( &binKMPri );
    if( nType < 0 )
    {
        berApplet->warningBox( tr( "Invalid private key" ), this );
        goto end;
    }

    ret = JS_PKCS7_makeDevelopedAndVerify( &binSrc, &binSignCert, &binKMPri, &binKMCert, &binOutput );
    berApplet->log( QString("developedAndVerify Results: %1").arg(ret));

    berApplet->logLine();
    berApplet->log( "-- Developed And Verify" );
    berApplet->logLine();
    berApplet->log( QString( "Src           : %1" ).arg( getHexString( &binSrc )));
    berApplet->log( QString( "Sign Cert     : %1" ).arg( getHexString( &binSignCert )));
    berApplet->log( QString( "KM PrivateKey : %1" ).arg( getHexString( &binKMPri )));
    berApplet->log( QString( "KM Cert       : %1" ).arg( getHexString( &binKMCert )));
    berApplet->log( QString( "Output        : %1" ).arg( getHexString( &binOutput )));
    berApplet->logLine();

    if( mOutputStringRadio->isChecked() )
        JS_BIN_string( &binOutput, &pOutput );
    else if( mOutputHexRadio->isChecked() )
        JS_BIN_encodeHex( &binOutput, &pOutput );
    else if( mOutputBase64Radio->isChecked() )
        JS_BIN_encodeBase64( &binOutput, &pOutput );

    mOutputText->setPlainText( pOutput );

end :
    if( pOutput ) JS_free( pOutput );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOutput );
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binKMPri );
    JS_BIN_reset( &binKMCert );
}

void CMSDlg::srcChanged()
{
    int nType = DATA_STRING;

    if( mSrcHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mSrcBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mSrcText->toPlainText() );
    mSrcLenText->setText( QString("%1").arg(strLen));
}

void CMSDlg::outputChanged()
{
    int nType = DATA_STRING;

    if( mOutputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mOutputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void CMSDlg::clickSignPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mSignPriKeyPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CMSDlg::clickSignCertView()
{
    QString strPath = mSignCertPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void CMSDlg::clickSignCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mSignCertPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CMSDlg::clickKMPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mKMPriKeyPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CMSDlg::clickKMCertView()
{
    QString strPath = mKMCertPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select a certificate", this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void CMSDlg::clickKMCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mKMCertPathText->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CMSDlg::clickSignPriKeyView()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;
    PriKeyInfoDlg priKeyInfo;

    ret = readSignPrivateKey( &binPri );
    if( ret != 0) return;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void CMSDlg::clickSignPriKeyType()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    ret = readSignPrivateKey( &binPri );
    if( ret != 0) return;
    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private key type for signing is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void CMSDlg::clickSignCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mSignCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate for signing"), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate type for signing is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void CMSDlg::clickKMPriKeyView()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    PriKeyInfoDlg priKeyInfo;

    ret = readKMPrivateKey( &binPri );
    if( ret != 0 ) return;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void CMSDlg::clickKMPriKeyType()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    ret = readKMPrivateKey( &binPri );
    if( ret != 0 ) return;
    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private key type for KM is %1").arg( getKeyTypeName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void CMSDlg::clickKMCertType()
{
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    int nType = -1;

    QString strPath = mKMCertPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Select a certificate for KM"), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );

    nType = JS_PKI_getPubKeyType( &binPubKey );

    berApplet->messageBox( tr( "Certificate type for KM is %1" ).arg( getKeyTypeName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}

void CMSDlg::clickClearDataAll()
{
    mSrcText->clear();
    mOutputText->clear();

    mSignPriKeyPathText->clear();
    mSignCertPathText->clear();
    mSignPasswdText->clear();

    mKMPriKeyPathText->clear();
    mKMCertPathText->clear();
    mKMPasswdText->clear();
}

void CMSDlg::clickReadFile()
{
    QString strPath;

    QString strFile = findFile( this, JS_FILE_TYPE_BER, strPath);

    if( strFile.length() > 0 )
    {
        BIN binData = {0,0};

        JS_BIN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binData );

        mSrcHexRadio->setChecked(true);
        mSrcText->setPlainText( getHexString( &binData ));
        JS_BIN_reset( &binData );
    }
}

void CMSDlg::checkSignEncPriKey()
{
    bool bVal = mSignEncPriKeyCheck->isChecked();

    mSignPasswdLabel->setEnabled(bVal);
    mSignPasswdText->setEnabled(bVal);
}

void CMSDlg::checkKMEncPriKey()
{
    bool bVal = mKMEncPriKeyCheck->isChecked();

    mKMPasswdLabel->setEnabled(bVal);
    mKMPasswdText->setEnabled(bVal);
}
