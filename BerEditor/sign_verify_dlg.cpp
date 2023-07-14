#include <QFileDialog>
#include <QFileInfo>
#include <QDateTime>

#include "sign_verify_dlg.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "cert_info_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"
#include "common.h"

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

static QStringList methodTypes = {
    "Signature",
    "Verify"
};

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    sctx_ = NULL;
    hctx_ = NULL;
    is_eddsa_ = false;


    setupUi(this);
    initialize();

    last_path_ = berApplet->getSetPath();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mAlgTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));
    connect( mMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMethod(int)));

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

    mCloseBtn->setFocus();
}

SignVerifyDlg::~SignVerifyDlg()
{
    if( sctx_ ) JS_PKI_signFree( &sctx_ );
    if( hctx_ ) JS_PKI_hashFree( &hctx_ );
}

void SignVerifyDlg::initialize()
{
    mAlgTypeCombo->addItems(algTypes);
    mHashTypeCombo->addItems(kHashList);
    mHashTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mVersionCombo->addItems(versionTypes);
    mMethodCombo->addItems(methodTypes);

    mAutoCertPubKeyCheck->setChecked(true);
    mUseKeyAlgCheck->setChecked(true);

    mInputTab->setCurrentIndex(0);

    checkAutoCertOrPubKey();
    checkUseKeyAlg();
    checkEncPriKey();
}

int SignVerifyDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPriKeyPath->text();

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to read private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncPrikeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "You have to insert password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt private key:%1").arg( ret ), this );
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

void SignVerifyDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

void SignVerifyDlg::checkPubKeyVerify()
{
    bool bVal = mPubKeyVerifyCheck->isChecked();

    if( bVal )
    {
        mCertBtn->setText( tr("Public Key" ) );
        mPriKeyAndCertLabel->setText( tr("Private key and Public key" ));
        mCertViewBtn->setEnabled(false);
    }
    else
    {
        mCertBtn->setText( tr("Certificate") );
        mPriKeyAndCertLabel->setText( tr( "Private key and Certificate" ));
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
        berApplet->elog( "You have to find cert" );
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

    if( ret == JS_VALID )
        berApplet->messageBox( tr("KeyPair is good"), this );
    else
        berApplet->warningBox( QString( tr("Invalid key pair: %1").arg(ret)), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
}

void SignVerifyDlg::findPrivateKey()
{
    QString strPath = mPriKeyPath->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    mPriKeyPath->setText(fileName);
    last_path_ = fileName;

    repaint();
}

void SignVerifyDlg::findCert()
{
    QString strPath = mCertPath->text();

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText( fileName );
    last_path_ = fileName;

    repaint();
}

void SignVerifyDlg::algChanged(int index)
{
    QString strAlg = mAlgTypeCombo->currentText();

    if( strAlg == "RSA" )
    {
        mVersionCombo->setEnabled(true);
    }
    else
    {
        mVersionCombo->setEnabled( false );
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
    }
    else
    {
        mDigestBtn->setEnabled(true);
    }
}

int SignVerifyDlg::signVerifyInit()
{
    int ret = 0;
    int nType = 0;
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};

    is_eddsa_ = false;

    if( sctx_ )
    {
        JS_PKI_signFree( &sctx_ );
        sctx_ = NULL;
    }

    if( hctx_ )
    {
        JS_PKI_hashFree( &hctx_ );
        hctx_ = NULL;
    }

    QString strHash = mHashTypeCombo->currentText();

    berApplet->log( QString( "Algorithm : %1 Hash : %2" ).arg( mAlgTypeCombo->currentText() ).arg( strHash ));

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;

        mOutputText->clear();

        if( mUseKeyAlgCheck->isChecked() )
        {
            nType = JS_PKI_getPriKeyType( &binPri );
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

        if( mAlgTypeCombo->currentText() == "RSA" )
            nType = JS_PKI_KEY_TYPE_RSA;
        else if( mAlgTypeCombo->currentText() == "SM2" )
            nType = JS_PKI_KEY_TYPE_SM2;
        else if( mAlgTypeCombo->currentText() == "DSA" )
            nType = JS_PKI_KEY_TYPE_DSA;
        else if( mAlgTypeCombo->currentText() == "Ed25519" )
        {
            nType = JS_PKI_KEY_TYPE_ED25519;
            is_eddsa_ = true;
        }
        else if( mAlgTypeCombo->currentText() == "Ed448" )
        {
            nType = JS_PKI_KEY_TYPE_ED448;
            is_eddsa_ = true;
        }
        else
            nType = JS_PKI_KEY_TYPE_ECC;

        ret = JS_PKI_signInit( &sctx_, strHash.toStdString().c_str(), nType, &binPri );

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Init Private Key : %1" ).arg( getHexString( &binPri )));
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            ret = -1;
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );

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
            nType = JS_PKI_getPubKeyType( &binPubKey );
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

        if( mAlgTypeCombo->currentText() == "RSA" )
            nType = JS_PKI_KEY_TYPE_RSA;
        else if( mAlgTypeCombo->currentText() == "SM2" )
            nType = JS_PKI_KEY_TYPE_SM2;
        else if( mAlgTypeCombo->currentText() == "DSA" )
            nType = JS_PKI_KEY_TYPE_DSA;
        else if( mAlgTypeCombo->currentText() == "Ed25519" )
        {
            nType = JS_PKI_KEY_TYPE_ED25519;
            is_eddsa_ = true;
        }
        else if( mAlgTypeCombo->currentText() == "Ed448" )
        {
            nType = JS_PKI_KEY_TYPE_ED448;
            is_eddsa_ = true;
        }
        else
            nType = JS_PKI_KEY_TYPE_ECC;

        ret = JS_PKI_verifyInit( &sctx_, strHash.toStdString().c_str(), nType, &binPubKey );

        berApplet->log( QString( "Algorithm       : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Init Public Key : %1" ).arg(getHexString(&binPubKey)));
    }

    if( is_eddsa_ == true )
    {
        ret = JS_PKI_hashInit( &hctx_, strHash.toStdString().c_str() );
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
    }
    else
        mStatusLabel->setText( QString("Init fail:%1").arg(ret) );

    repaint();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPubKey );
    return ret;
}

void SignVerifyDlg::signVerifyUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    int nDataType = DATA_HEX;
    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
    }

    if( mInputStringRadio->isChecked() )
        nDataType = DATA_STRING;
    else if( mInputBase64Radio->isChecked() )
        nDataType = DATA_BASE64;

    getBINFromString( &binSrc, nDataType, strInput );

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( is_eddsa_ )
            ret = JS_PKI_hashUpdate( hctx_, &binSrc );
        else
            ret = JS_PKI_signUpdate( sctx_, &binSrc );

        berApplet->log( QString("Update Src : %1").arg( getHexString(&binSrc)));
    }
    else
    {
        if( is_eddsa_ )
            ret = JS_PKI_hashUpdate( hctx_, &binSrc );
        else
            ret = JS_PKI_verifyUpdate( sctx_, &binSrc );

        berApplet->log( QString("Update Src : %1").arg( getHexString(&binSrc)));
    }

    if( ret == 0 )
    {
        appendStatusLabel( "|Update OK" );
    }
    else
        mStatusLabel->setText( QString("Update Fail:%1").arg( ret) );

    repaint();
    JS_BIN_reset( &binSrc );
}

void SignVerifyDlg::signVerifyFinal()
{
    int ret = 0;
    BIN binSign = {0,0};
    BIN binDigest = {0,0};

    if( is_eddsa_ )
    {
        ret = JS_PKI_hashFinal( hctx_, &binDigest );
        if( ret != 0 ) goto end;
    }

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( is_eddsa_ )
        {
            ret = JS_PKI_sign( sctx_, &binDigest, &binSign );
        }
        else
        {
            ret = JS_PKI_signFinal( sctx_, &binSign );
        }

        if( ret == 0 )
        {
            char *pHex = NULL;
            JS_BIN_encodeHex( &binSign, &pHex );
            mOutputText->setPlainText( pHex );
            JS_free( pHex );
        }

        berApplet->log( QString( "Final Signature : %1" ).arg( getHexString(&binSign)));

        if( ret == 0 )
        {
            mStatusLabel->setText( "Final OK" );
        }
        else
            mStatusLabel->setText( QString("Final Fail:%1").arg(ret) );
    }
    else
    {
        QString strOut = mOutputText->toPlainText();
        JS_BIN_decodeHex( strOut.toStdString().c_str(), &binSign );

        if( is_eddsa_ )
            ret = JS_PKI_verify( sctx_, &binDigest, &binSign );
        else
            ret = JS_PKI_verifyFinal( sctx_, &binSign );

        if( ret == JS_VERIFY )
            berApplet->messageBox( tr("Verify Success"), this );
        else {
            berApplet->warningBox( tr("Verify Fail"), this );
        }

        if( ret == JS_VERIFY )
        {
            appendStatusLabel( "|Final OK" );
        }
        else
            mStatusLabel->setText( QString("Final Fail:%1").arg(ret) );
    }


end :
    JS_BIN_reset( &binDigest );
    JS_BIN_reset( &binSign );

    if( sctx_ ) JS_PKI_signFree( &sctx_ );
    if( hctx_ ) JS_PKI_hashFree( &hctx_ );
    is_eddsa_ = false;

    repaint();
}

void SignVerifyDlg::Run()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        dataRun();
    else
        fileRun();
}

void SignVerifyDlg::dataRun()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPubKey = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;

    int nDataType = DATA_HEX;
    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
//        berApplet->warningBox( tr( "You have to insert data"), this );
//        return;
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

    QString strHash = mHashTypeCombo->currentText();

    berApplet->log( QString( "Algorithm : %1 Hash %2").arg( mAlgTypeCombo->currentText()).arg( strHash ));

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {   
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;

        if( mUseKeyAlgCheck->isChecked() )
        {
            int nAlgType = JS_PKI_getPriKeyType( &binPri );
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

            BIN binDigest = {0,0};
            JS_PKI_genHash( strAlg.toStdString().c_str(), &binSrc, &binDigest );
            berApplet->log( QString( "Hash Value: %1").arg( getHexString(&binDigest)));

            ret = JS_PKI_EdDSA_Sign( nParam, &binDigest, &binPri, &binOut );

            JS_BIN_reset( &binDigest );
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Sign Src         : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
        berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));

        if( ret == 0 )
            mStatusLabel->setText( "Sign OK" );
        else
            mStatusLabel->setText( QString("Sign Fail:%1").arg(ret));
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
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
            BIN binDigest = {0,0};
            JS_PKI_genHash( strAlg.toStdString().c_str(), &binSrc, &binDigest );
            berApplet->log( QString( "Hash Value: %1").arg( getHexString(&binDigest)));

            ret = JS_PKI_EdDSA_Verify( &binDigest, &binOut, &binPubKey );
            JS_BIN_reset( &binDigest );
        }

        berApplet->log( QString( "Algorithm         : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Verify Src        : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Verify Public Key : %1" ).arg(getHexString( &binPubKey )));

        if( ret == JS_VERIFY )
        {
            mStatusLabel->setText( "Verify OK" );
        }
        else
            mStatusLabel->setText( QString("Verify Fail:%1").arg(ret) );

        if( ret == JS_VERIFY )
            berApplet->messageBox( tr("Verify Success"), this );
        else {
            berApplet->warningBox( tr("Verify Fail"), this );
        }
    }

    repaint();
end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
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
    int nUpdateCnt = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};


    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("You have to find src file"), this );
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
        berApplet->elog( QString( "fail to read file:%1").arg( strSrcFile ));
        goto end;
    }

    berApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));


    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        if( mWriteLogCheck->isChecked() )
        {
            berApplet->log( QString( "Read[%1:%2] %3").arg( nOffset ).arg( nRead ).arg( getHexString(&binPart)));
        }

        if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
        {
            ret = JS_PKI_signUpdate( sctx_, &binPart );
        }
        else
        {
            ret = JS_PKI_verifyUpdate( sctx_, &binPart );
        }

        if( ret != 0 )
        {
            berApplet->elog( QString( "fail to update sign or verify : %1").arg(ret));
            break;
        }

        nUpdateCnt++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mSignProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        repaint();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mSignProgBar->setValue( 100 );

        if( ret == 0 )
        {
            QString strStatus = QString( "|Update X %1").arg( nUpdateCnt );
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

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
    }

    if( mInputStringRadio->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexRadio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    }
    else if( mInputBase64Radio->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
    }

    if( mVersionCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    QString strHash = mHashTypeCombo->currentText();

    berApplet->log( QString( "Algorithm : %1 Hash %2").arg( mAlgTypeCombo->currentText()).arg( strHash ));

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {        
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;

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
        mOutputText->setPlainText(pOut);

        berApplet->log( QString( "Algorithm        : %1" ).arg( mAlgTypeCombo->currentText() ));
        berApplet->log( QString( "Sign Digest Src  : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Sign Private Key : %1" ).arg(getHexString( &binPri )));
        berApplet->log( QString( "Signature        : %1" ).arg( getHexString( &binOut )));

        if( ret == 0 )
            mStatusLabel->setText( "SignDigest OK" );
        else
            mStatusLabel->setText( QString("SignDigest Fail:%1").arg(ret));
    }
    else
    {
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );
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

        if( ret == JS_VERIFY )
        {
            mStatusLabel->setText( "VerifyDigest OK" );
        }
        else
            mStatusLabel->setText( QString("VerifyDigest Fail:%1").arg(ret) );

        if( ret == JS_VERIFY )
            berApplet->messageBox( tr("Verify Success"), this );
        else {
            berApplet->warningBox( tr("Verify Fail"), this );
        }
    }

    repaint();
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

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void SignVerifyDlg::outputChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void SignVerifyDlg::changeMethod( int index )
{
    if( index == 0 )
    {
        mRunBtn->setText( tr( "Sign" ));
        mDigestBtn->setText( tr( "SignDigest" ));
    }
    else
    {
        mRunBtn->setText( tr( "Verify"));
        mDigestBtn->setText( tr( "VerifyDigest" ));
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

void SignVerifyDlg::clickPriKeyDecode()
{
    BIN binData = {0,0};
    QString strPath = mPriKeyPath->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void SignVerifyDlg::clickCertView()
{
    QString strPath = mCertPath->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("You have to find certificate"), this );
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void SignVerifyDlg::clickCertDecode()
{
    BIN binData = {0,0};
    QString strPath = mCertPath->text();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("fail to read data"), this );
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
        berApplet->warningBox( tr( "You have to find certificate or public key"), this );
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
    QString strPath;
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
