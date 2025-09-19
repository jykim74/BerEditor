/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QButtonGroup>

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

static QStringList algTypes = {
    "RSA",
    "SM2",
    "ECIES"
};

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};


static QStringList versionTypes = {
    "V15",
    "V21"
};

PubEncDecDlg::PubEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(changeValue()));
    connect( mAutoCertPubKeyCheck, SIGNAL(clicked()), this, SLOT(checkAutoCertOrPubKey()));
    connect( mPubKeyEncryptCheck, SIGNAL(clicked()), this, SLOT(checkPubKeyEncrypt()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));

    connect( mEncryptRadio, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptRadio, SIGNAL(clicked()), this, SLOT(clickDecrypt()));

    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outputChanged()));
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged()));

    connect( mPriKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyView()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

    connect( mUseKeyAlgCheck, SIGNAL(clicked()), this, SLOT(checkUseKeyAlg()));
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

    mRunBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCertGroup->layout()->setSpacing(5);

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

void PubEncDecDlg::initialize()
{
    mAlgCombo->addItems( algTypes );

    mOutputTypeCombo->addItems(dataTypes);
    mOutputTypeCombo->setCurrentIndex(1);

    mVersionTypeCombo->addItems(versionTypes);
    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mEncryptRadio );
    runGroup->addButton( mDecryptRadio );

    mAutoCertPubKeyCheck->setChecked(true);
    mUseKeyAlgCheck->setChecked(true);

    checkAutoCertOrPubKey();
    checkUseKeyAlg();
    checkEncPriKey();

    mEncryptRadio->click();

    mPriKeyPath->setPlaceholderText( tr("Select a private key") );
    mCertPath->setPlaceholderText( tr( "Select a certificate" ));
    mIVText->setPlaceholderText( tr( "Hex value" ));
    mTagText->setPlaceholderText( tr( "Hex value" ));
    mOtherPubText->setPlaceholderText( tr( "Hex value" ));
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

void PubEncDecDlg::checkPubKeyEncrypt()
{
    bool bVal = mPubKeyEncryptCheck->isChecked();
    mCertViewBtn->setEnabled( !bVal );

    if( bVal )
    {
        mCertLabel->setText(tr("PublicKey"));
        mCertGroup->setTitle( tr("Private key and Public key" ));
    }
    else
    {
        mCertLabel->setText(tr("Certificate"));
        mCertGroup->setTitle( tr("Private key and Certificate"));
    }
}

void PubEncDecDlg::checkAutoCertOrPubKey()
{
    bool bVal = mAutoCertPubKeyCheck->isChecked();

    mPubKeyEncryptCheck->setEnabled( !bVal );
}

void PubEncDecDlg::clickCheckKeyPair()
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
        berApplet->elog( "Select a publick key" );
        return;
    }

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

    if( mAutoCertPubKeyCheck->isChecked() )
    {
        if( JS_PKI_isCert( &binCert ) == 0 )
            mPubKeyEncryptCheck->setChecked( true );
        else
            mPubKeyEncryptCheck->setChecked( false );
    }

    if( mPubKeyEncryptCheck->isChecked() )
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
        berApplet->warningBox( QString( tr("The keypair is incorrect [%1]")).arg(ret), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
}

void PubEncDecDlg::Run()
{
    int ret = 0;
    int nVersion = 0;
    int nDataType = DATA_HEX;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binOut = {0,0};
    BIN binPubKey = {0,0};
    char *pOut = NULL;

    QString strAlg = mAlgCombo->currentText();
    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "Enter your data"), this );
        mInputText->setFocus();
        return;
    }

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;
    else
        nDataType = DATA_HEX;

    getBINFromString( &binSrc, nDataType, strInput );

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
                berApplet->warningBox( tr( "Select a certificate"), this );
                mCertPath->setFocus();
                goto end;
            }

            JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
            if( mAutoCertPubKeyCheck->isChecked() )
            {
                if( JS_PKI_isCert( &binCert ) == 0 )
                {
                    mPubKeyEncryptCheck->setChecked(true);
                    JS_BIN_copy( &binPubKey, &binCert );
                }
                else
                {
                    mPubKeyEncryptCheck->setChecked(false);
                    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
                }
            }
            else
            {
                if( mPubKeyEncryptCheck->isChecked() == false )
                    JS_PKI_getPubKeyFromCert( &binCert, &binPubKey );
                else
                    JS_BIN_copy( &binPubKey, &binCert );
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
                keyPairMan.setTitle( tr( "Select keypair" ));
                keyPairMan.setMode( KeyPairModeSelect );

                if( keyPairMan.exec() != QDialog::Accepted )
                    goto end;

                strPubPath = keyPairMan.getPubPath();
                JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPubKey );
            }
        }



        int nAlgType = JS_PKI_getPubKeyType( &binPubKey );
        QString strKeyType = JS_PKI_getKeyAlgName( nAlgType );

        if( mUseKeyAlgCheck->isChecked() )
        {
            berApplet->log( QString( "PubKey Type : %1").arg( strKeyType));

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgCombo->setCurrentText( "SM2" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ECDSA )
                mAlgCombo->setCurrentText( "ECIES" );
            else
            {
                berApplet->warningBox( tr( "Invalid public key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }
        }

        if( mAlgCombo->currentText() == "RSA" )
        {
            if( nAlgType != JS_PKI_KEY_TYPE_RSA )
            {
                berApplet->warningBox( tr( "Invalid public key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }

            ret = JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binPubKey, &binOut );
        }
        else if( mAlgCombo->currentText() == "SM2" )
        {
            if( nAlgType != JS_PKI_KEY_TYPE_SM2 )
            {
                berApplet->warningBox( tr( "Invalid public key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }

            ret = JS_PKI_SM2EncryptWithPub( &binSrc, &binPubKey, &binOut );
        }
        else if( mAlgCombo->currentText() == "ECIES" )
        {
            BIN binOtherPub = {0,0};
            BIN binIV = {0,0};
            BIN binTag = {0,0};

            if( nAlgType != JS_PKI_KEY_TYPE_ECDSA )
            {
                berApplet->warningBox( tr( "Invalid public key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }

            ret = JS_ECIES_Encrypt( &binSrc, &binPubKey, &binOtherPub, &binIV, &binTag, &binOut );
            if( ret == 0 )
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

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- Public Encrypt" );
            berApplet->logLine2();
            berApplet->log( QString( "Algorithm     : %1").arg( mAlgCombo->currentText() ));
            berApplet->log( QString( "Enc Src       : %1").arg( getHexString(&binSrc)));
            berApplet->log( QString( "Enc PublicKey : %1").arg(getHexString(&binPubKey)));
            berApplet->log( QString( "Enc Output    : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();

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

        int nAlgType = JS_PKI_getPriKeyType( &binPri );
        QString strKeyType = JS_PKI_getKeyAlgName( nAlgType );

        if( mUseKeyAlgCheck->isChecked() )
        {
            berApplet->log( QString( "PriKey Type : %1").arg( strKeyType ));

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgCombo->setCurrentText( "SM2" );
            else if( nAlgType == JS_PKI_KEY_TYPE_ECDSA )
                mAlgCombo->setCurrentText( "ECIES" );
            else
            {
                berApplet->warningBox( tr( "Invalid private key algorithm: %1").arg( strKeyType ), this );
                goto end;
            }
        }

        if( mAlgCombo->currentText() == "RSA" )
        {
            if( nAlgType != JS_PKI_KEY_TYPE_RSA )
            {
                berApplet->warningBox( tr( "Invalid private key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }

            ret = JS_PKI_RSADecryptWithPri( nVersion, &binSrc, &binPri, &binOut );
        }
        else if( mAlgCombo->currentText() == "SM2" )
        {
            if( nAlgType != JS_PKI_KEY_TYPE_SM2 )
            {
                berApplet->warningBox( tr( "Invalid private key algorithm:%1").arg( strKeyType ), this );
                goto end;
            }

            ret = JS_PKI_SM2DecryptWithPri( &binSrc, &binPri, &binOut );
        }
        else if( mAlgCombo->currentText() == "ECIES" )
        {
            BIN binOtherPub = {0,0};
            BIN binIV = {0,0};
            BIN binTag = {0,0};

            QString strOtherPub = mOtherPubText->toPlainText();
            QString strIV = mIVText->text();
            QString strTag = mTagText->text();

            JS_BIN_decodeHex( strOtherPub.toStdString().c_str(), &binOtherPub );
            JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
            JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

            ret = JS_ECIES_Decrypt( &binSrc, &binPri, &binOtherPub, &binIV, &binTag, &binOut );

            if( ret == 0 )
            {
                berApplet->logLine();
                berApplet->log( "-- ECIES Decrypt" );
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

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- Private Decrypt" );
            berApplet->logLine2();
            berApplet->log( QString( "Algorithm      : %1").arg( mAlgCombo->currentText() ));
            berApplet->log( QString( "Dec Src        : %1").arg( getHexString(&binSrc)));
            berApplet->log( QString( "Dec PrivateKey : [hidden]"));
            berApplet->log( QString( "Dec Output     : %1" ).arg( getHexString( &binOut )));
            berApplet->logLine();

            berApplet->messageLog( tr( "Private key decryption success" ), this );
        }
        else
        {
            berApplet->warnLog( tr( "Private key decryption failed: %1").arg( ret ), this );
        }
    }

    if( mOutputTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_string( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_encodeHex( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_encodeBase64( &binOut, &pOut );

    mOutputText->setPlainText(pOut);

end :
    update();

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binCert);
    JS_BIN_reset(&binOut);
    JS_BIN_reset( &binPubKey );

    if( pOut ) JS_free(pOut);
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

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    mOutputText->clear();
    mInputText->setPlainText( strOutput );

    update();
}

void PubEncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void PubEncDecDlg::outputChanged()
{
    QString strLen = getDataLenString( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void PubEncDecDlg::algChanged()
{
    QString strAlg = mAlgCombo->currentText();

    if( mUseKeyAlgCheck->isChecked() == false )
    {
        if( strAlg == "RSA" )
        {
            mVersionLabel->setEnabled( true );
            mVersionTypeCombo->setEnabled( true );
        }
        else
        {
            mVersionLabel->setEnabled( false );
            mVersionTypeCombo->setEnabled( false );
        }

        if( strAlg == "ECIES" )
            mECIESGroup->setEnabled( true );
        else
            mECIESGroup->setEnabled( false );
    }
    else
    {
        mVersionTypeCombo->setEnabled( true );
    }
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

    berApplet->messageBox( tr( "%1 Type is %2").arg( strKind).arg( JS_PKI_getKeyAlgName(nType)), this);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
}


void PubEncDecDlg::checkUseKeyAlg()
{
    bool bVal = mUseKeyAlgCheck->isChecked();

    mAlgCombo->setEnabled( !bVal );
    algChanged();
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

void PubEncDecDlg::clickEncrypt()
{
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

void PubEncDecDlg::clickDecrypt()
{
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
            clickEncrypt();
        else
            clickDecrypt();
    }
}
