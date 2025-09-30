/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QButtonGroup>
#include <QElapsedTimer>

#include "pub_enc_dec_dlg.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"
#include "settings_mgr.h"
#include "key_pair_man_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"
#include "js_pki_tools.h"
#include "js_ecies.h"
#include "js_error.h"

static QStringList versionTypes = {
    "V15",
    "V21"
};

PubEncDecDlg::PubEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(changeValue()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));

    connect( mEncryptRadio, SIGNAL(clicked()), this, SLOT(checkEncrypt()));
    connect( mDecryptRadio, SIGNAL(clicked()), this, SLOT(checkDecrypt()));

    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));

    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outputChanged()));

    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyView()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyType()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickCertType()));
    connect( mEncPrikeyCheck, SIGNAL(clicked()), this, SLOT(checkEncPriKey()));

    connect( mOtherPubText, SIGNAL(textChanged()), this, SLOT(changeOtherPub()));
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(changeIV(const QString&)));
    connect( mTagText, SIGNAL(textChanged(const QString&)), this, SLOT(changeTag(const QString&)));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    connect( mCertGroup, SIGNAL(clicked()), this, SLOT(checkCertGroup()));


    initialize();

    mRunBtn->setDefault(true);
    mInputText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mPriKeyViewBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);
    mPriKeyDecodeBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mCertViewBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PubEncDecDlg::~PubEncDecDlg()
{

}

void PubEncDecDlg::initUI()
{
    mInputTypeCombo->addItems( kDataTypeList );
    mOutputTypeCombo->addItems( kDataTypeList );

    mPriKeyPath->setPlaceholderText( tr("Select a private key") );
    mCertPath->setPlaceholderText( tr( "Select a certificate" ));
    mIVText->setPlaceholderText( tr( "Hex value" ));
    mTagText->setPlaceholderText( tr( "Hex value" ));
    mOtherPubText->setPlaceholderText( tr( "Hex value" ));
}

void PubEncDecDlg::initialize()
{
    mVersionTypeCombo->addItems(versionTypes);
    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mEncryptRadio );
    runGroup->addButton( mDecryptRadio );

    checkEncPriKey();

    mEncryptRadio->click();
}

int PubEncDecDlg::readPrivateKey( BIN *pPriKey )
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
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
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

void PubEncDecDlg::setReadOnlyECIES( bool bVal )
{
    mIVText->setReadOnly( bVal );
    mTagText->setReadOnly( bVal );
    mOtherPubText->setReadOnly( bVal );

    if( bVal == true )
    {
        mIVText->setStyleSheet( kReadOnlyStyle );
        mTagText->setStyleSheet( kReadOnlyStyle );
        mOtherPubText->setStyleSheet( kReadOnlyStyle );
    }
    else
    {
        mIVText->setStyleSheet( "" );
        mTagText->setStyleSheet( "" );
        mOtherPubText->setStyleSheet( "" );
    }
}

void PubEncDecDlg::Run()
{
    int ret = 0;
    int nVersion = 0;

    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binOut = {0,0};
    BIN binPubKey = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString strAlg;
    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();
    QString strOut;

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Enter your data"), this );
        mInputText->setFocus();
        return;
    }

    getBINFromString( &binSrc, strType, strInput );

    if( mVersionTypeCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    if( mEncryptRadio->isChecked() )
    {
        if( mCertGroup->isChecked() == true )
        {
            QString strCertPath = mCertPath->text();

            if( strCertPath.length() < 1 )
            {
                berApplet->warningBox( tr( "Select a certificate or public key"), this );
                mCertPath->setFocus();
                goto end;
            }

            JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
            if( JS_PKI_isCert( &binCert ) == 0 )
            {
                JS_BIN_copy( &binPubKey, &binCert );
            }
            else
            {
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
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
                    goto end;

                strCertHex = certMan.getCertHex();
                JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &binCert );
                JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
            }
            else
            {
                QString strPubPath;

                KeyPairManDlg keyPairMan;
                keyPairMan.setTitle( tr( "Select a public key" ));
                keyPairMan.setMode( KeyPairModeSelect );

                if( keyPairMan.exec() != QDialog::Accepted )
                    goto end;

                strPubPath = keyPairMan.getPubPath();
                JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPubKey );
            }
        }

        int nKeyType = JS_PKI_getPubKeyType( &binPubKey );
        QString strKeyAlg = JS_PKI_getKeyAlgName( nKeyType );

        if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_SM2 && nKeyType != JS_PKI_KEY_TYPE_ECDSA )
        {
            berApplet->warningBox( tr( "This key algorithm (%1) is not supported" ).arg(strKeyAlg), this );
            goto end;
        }

        if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        {
            timer.start();
            ret = JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binPubKey, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( nKeyType == JS_PKI_KEY_TYPE_SM2 )
        {
            timer.start();
            ret = JS_PKI_SM2EncryptWithPub( &binSrc, &binPubKey, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
        {
            BIN binOtherPub = {0,0};
            BIN binIV = {0,0};
            BIN binTag = {0,0};

            strKeyAlg = "ECIES";

            timer.start();
            ret = JS_ECIES_Encrypt( &binSrc, &binPubKey, &binOtherPub, &binIV, &binTag, &binOut );
            us = timer.nsecsElapsed() / 1000;

            if( ret == JSR_OK )
            {
                mOtherPubText->setPlainText( getHexString( &binOtherPub ));
                mIVText->setText( getHexString( &binIV ));
                mTagText->setText( getHexString( &binTag ));

                berApplet->logLine();
                berApplet->log( "-- ECIES Encrypt" );
                berApplet->logLine2();
                berApplet->log( QString( "ECIES OtherPub : %1").arg( getHexString(&binOtherPub)));
                berApplet->log( QString( "ECIES IV       : %1").arg( getHexString(&binIV)));
                berApplet->log( QString( "ECIES Tag      : %1" ).arg( getHexString( &binTag )));
                berApplet->logLine();
            }

            JS_BIN_reset( &binOtherPub );
            JS_BIN_reset( &binIV );
            JS_BIN_reset( &binTag );
        }

        if( ret == JSR_OK )
        {
            berApplet->logLine();
            berApplet->log( QString( "-- Public Encrypt [time: %1 ms]" ).arg( getMS( us )) );
            berApplet->logLine2();
            berApplet->log( QString( "Algorithm     : %1").arg( strKeyAlg ));
            berApplet->log( QString( "Enc Src       : %1").arg( getHexString(&binSrc)));
            berApplet->log( QString( "Enc PublicKey : %1").arg(getHexString(&binPubKey)));
            berApplet->log( QString( "Enc Output    : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();

            strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
            mOutputText->setPlainText( strOut );

            berApplet->messageLog( tr( "Public key encryption success" ), this );
        }
        else
        {
            berApplet->warnLog( tr( "Public key encryption failed: %1").arg( ret ), this );
        }
    }
    else {

        if( mCertGroup->isChecked() == true )
        {
            ret = readPrivateKey( &binPri );
            if( ret != 0 ) goto end;
        }
        else
        {
            if( mUseCertManCheck->isChecked() == true )
            {
                CertManDlg certMan;
                QString strPriHex;

                certMan.setMode(ManModeSelBoth);
                if( certMan.exec() != QDialog::Accepted )
                    goto end;

                strPriHex = certMan.getPriKeyHex();
                JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binPri );
            }
            else
            {
                QString strPriPath;

                KeyPairManDlg keyPairMan;
                keyPairMan.setTitle( tr( "Select keypair" ));
                keyPairMan.setMode( KeyPairModeSelect );

                if( keyPairMan.exec() != QDialog::Accepted )
                    goto end;

                strPriPath = keyPairMan.getPriPath();

                JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
            }
        }

        int nKeyType = JS_PKI_getPriKeyType( &binPri );
        QString strKeyAlg = JS_PKI_getKeyAlgName( nKeyType );

        if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_SM2 && nKeyType != JS_PKI_KEY_TYPE_ECDSA )
        {
            berApplet->warningBox( tr( "This key algorithm (%1) is not supported" ).arg(strKeyAlg), this );
            goto end;
        }

        if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        {
            timer.start();
            ret = JS_PKI_RSADecryptWithPri( nVersion, &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( nKeyType == JS_PKI_KEY_TYPE_SM2 )
        {
            timer.start();
            ret = JS_PKI_SM2DecryptWithPri( &binSrc, &binPri, &binOut );
            us = timer.nsecsElapsed() / 1000;
        }
        else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
        {
            BIN binOtherPub = {0,0};
            BIN binIV = {0,0};
            BIN binTag = {0,0};

            QString strOtherPub = mOtherPubText->toPlainText();
            QString strIV = mIVText->text();
            QString strTag = mTagText->text();

            strKeyAlg = "ECIES";

            JS_BIN_decodeHex( strOtherPub.toStdString().c_str(), &binOtherPub );
            JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
            JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

            timer.start();
            ret = JS_ECIES_Decrypt( &binSrc, &binPri, &binOtherPub, &binIV, &binTag, &binOut );
            us = timer.nsecsElapsed() / 1000;

            if( ret == JSR_OK )
            {
                berApplet->logLine();
                berApplet->log( QString( "-- ECIES Decrypt" ) );
                berApplet->logLine2();
                berApplet->log( QString( "ECIES OtherPub : %1").arg( getHexString(&binOtherPub)));
                berApplet->log( QString( "ECIES IV       : %1").arg( getHexString(&binIV)));
                berApplet->log( QString( "ECIES Tag      : %1" ).arg( getHexString( &binTag )));
                berApplet->logLine();
            }

            JS_BIN_reset( &binOtherPub );
            JS_BIN_reset( &binIV );
            JS_BIN_reset( &binTag );
        }

        if( ret == JSR_OK )
        {
            berApplet->logLine();
            berApplet->log( QString( "-- Private Decrypt [time: %1 ms]" ).arg( getMS( us )) );
            berApplet->logLine2();
            berApplet->log( QString( "Algorithm      : %1").arg( strKeyAlg ));
            berApplet->log( QString( "Dec Src        : %1").arg( getHexString(&binSrc)));
            berApplet->log( QString( "Dec PrivateKey : [hidden]"));
            berApplet->log( QString( "Dec Output     : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();

            strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
            mOutputText->setPlainText( strOut );

            berApplet->messageLog( tr( "Private key decryption success" ), this );
        }
        else
        {
            berApplet->warnLog( tr( "Private key decryption failed: %1").arg( ret ), this );
        }
    }

end :
    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binCert);
    JS_BIN_reset(&binOut);
    JS_BIN_reset( &binPubKey );
}

void PubEncDecDlg::findCert()
{
    QString strPath = mCertPath->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText(fileName);

    update();
}

void PubEncDecDlg::findPrivateKey()
{
    QString strPath = mPriKeyPath->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);

    update();
}

void PubEncDecDlg::changeValue()
{
    QString strOutput = mOutputText->toPlainText();
    QString strOutputType = mOutputTypeCombo->currentText();

    mInputTypeCombo->setCurrentText( strOutputType );

    mOutputText->clear();
    mInputText->setPlainText( strOutput );

    update();
}

void PubEncDecDlg::inputChanged()
{    
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void PubEncDecDlg::outputChanged()
{
    QString strLen = getDataLenString( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void PubEncDecDlg::clickPriKeyView()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;
    PriKeyInfoDlg priKeyInfo;

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
}

void PubEncDecDlg::clickPriKeyDecode()
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

void PubEncDecDlg::clickCertView()
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

void PubEncDecDlg::clickCertDecode()
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

void PubEncDecDlg::clickPriKeyType()
{
    int ret = 0;
    BIN binPri = {0,0};
    int nType = -1;

    ret = readPrivateKey( &binPri );
    if( ret != 0 ) goto end;

    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private Key Type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

end :
    JS_BIN_reset( &binPri );
}

void PubEncDecDlg::clickCertType()
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


void PubEncDecDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mPriKeyPath->clear();
    mCertPath->clear();
    mPasswdText->clear();
    mOtherPubText->clear();
    mIVText->clear();
    mTagText->clear();
}

void PubEncDecDlg::checkEncPriKey()
{
    bool bVal = mEncPrikeyCheck->isChecked();

    mPasswdLabel->setEnabled(bVal);
    mPasswdText->setEnabled(bVal);
}

void PubEncDecDlg::changeOtherPub()
{
    QString strLen = getDataLenString( DATA_HEX, mOtherPubText->toPlainText() );
    mOtherPubLenText->setText( QString( "%1" ).arg(strLen) );
}

void PubEncDecDlg::changeIV( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mIVLenText->setText( QString( "%1" ).arg(strLen) );
}

void PubEncDecDlg::changeTag( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mTagLenText->setText( QString( "%1" ).arg(strLen) );
}

void PubEncDecDlg::checkEncrypt()
{
    mHeadLabel->setText( tr( "Public key encryption" ) );
    mInputLabel->setText( tr( "Source data" ) );
    mOutputLabel->setText( tr( "Encrypted data" ) );

    mOtherPubText->setPlaceholderText( tr("Hex value generated during encryption") );
    mIVText->setPlaceholderText( tr("Hex value generated during encryption") );
    mTagText->setPlaceholderText( tr("Hex value generated during encryption") );

    setReadOnlyECIES( true );

    mRunBtn->setText( tr("Encrypt" ));

    if( mCertGroup->isChecked() )
    {
        mCertPath->setEnabled(true);
        mPriKeyPath->setEnabled(false);
    }
    else
    {
        mCertPath->setEnabled(false);
        mPriKeyPath->setEnabled(false);
    }
}

void PubEncDecDlg::checkDecrypt()
{
    mHeadLabel->setText( tr( "Private key decryption" ) );
    mInputLabel->setText( tr( "Encrypted data" ) );
    mOutputLabel->setText( tr( "Decrypted data" ) );

    mOtherPubText->setPlaceholderText( tr("Hex value") );
    mIVText->setPlaceholderText( tr("Hex value") );
    mTagText->setPlaceholderText( tr("Hex value") );

    setReadOnlyECIES( false );

    mRunBtn->setText( tr("Decrypt" ) );

    if( mCertGroup->isChecked() == true )
    {
        mCertPath->setEnabled(false);
        mPriKeyPath->setEnabled(true);
    }
    else
    {
        mCertPath->setEnabled(false);
        mPriKeyPath->setEnabled(false);
    }
}

void PubEncDecDlg::clickInputClear()
{
    mInputText->clear();
}

void PubEncDecDlg::clickOutputClear()
{
    mOutputText->clear();
}

void PubEncDecDlg::checkCertGroup()
{
    if( mCertGroup->isChecked() == true )
    {
        if( mEncryptRadio->isChecked() == true )
            checkEncrypt();
        else
            checkDecrypt();
    }
}
