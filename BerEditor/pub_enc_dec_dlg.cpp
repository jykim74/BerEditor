#include <QFileDialog>

#include "pub_enc_dec_dlg.h"
#include "cert_info_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"
#include "js_pki_tools.h"

static QStringList algTypes = {
    "RSA",
    "SM2"
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

static QStringList methodTypes = {
    "Encrypt",
    "Decrypt"
};

PubEncDecDlg::PubEncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();
    last_path_ = berApplet->getSetPath();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(changeValue()));
    connect( mAutoCertPubKeyCheck, SIGNAL(clicked()), this, SLOT(checkAutoCertOrPubKey()));
    connect( mPubKeyEncryptCheck, SIGNAL(clicked()), this, SLOT(checkPubKeyEncrypt()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));

    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outputChanged()));
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged()));

    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyDecode()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertView()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCertDecode()));

    connect( mUseKeyAlgCheck, SIGNAL(clicked()), this, SLOT(checkUseKeyAlg()));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(clickPriKeyType()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(clickCertType()));

    mCloseBtn->setFocus();
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
    mMethodTypeCombo->addItems(methodTypes);

    mAutoCertPubKeyCheck->setChecked(true);
    mUseKeyAlgCheck->setChecked(true);

    checkAutoCertOrPubKey();
    checkUseKeyAlg();
}

void PubEncDecDlg::checkPubKeyEncrypt()
{
    bool bVal = mPubKeyEncryptCheck->isChecked();
    mCertViewBtn->setEnabled( !bVal );

    if( bVal )
    {
        mCertBtn->setText(tr("Public Key"));
        mPriKeyAndCertLabel->setText( tr("Private key and Public key" ));
    }
    else
    {
        mCertBtn->setText(tr("Certificate"));
        mPriKeyAndCertLabel->setText( tr("Private key and Certificate"));
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

    QString strPriPath = mPriKeyPath->text();
    QString strCertPath = mCertPath->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->elog( "You have to find private key" );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->elog( "You have to find publick key" );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
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

    if( ret == JS_VALID )
        berApplet->messageBox( tr("KeyPair is good"), this );
    else
        berApplet->warningBox( QString( tr("Invalid key pair: %1")).arg(ret), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
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
    char *pOut = NULL;

    QString strAlg = mAlgCombo->currentText();
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

    if( mVersionTypeCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));

    if( mMethodTypeCombo->currentIndex() == ENC_ENCRYPT )
    {     
        if( mCertBtn->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileReadBER( mCertPath->text().toLocal8Bit().toStdString().c_str(), &binCert );

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

        if( mUseKeyAlgCheck->isChecked() )
        {
            int nAlgType = JS_PKI_getPubKeyType( &binPubKey );
            berApplet->log( QString( "PubKey Type : %1").arg( getKeyTypeName( nAlgType )));

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgCombo->setCurrentText( "SM2" );
            else
            {
                berApplet->warningBox( tr( "Invalid private key algorithm"), this );
                goto end;
            }
        }

        if( mAlgCombo->currentText() == "RSA" )
        {
            JS_PKI_RSAEncryptWithPub( nVersion, &binSrc, &binPubKey, &binOut );
        }
        else
        {
            JS_PKI_SM2EncryptWithPub( &binSrc, &binPubKey, &binOut );
        }

        berApplet->log( QString( "Algorithm     : %1").arg( mAlgCombo->currentText() ));
        berApplet->log( QString( "Enc Src       : %1").arg( getHexString(&binSrc)));
        berApplet->log( QString( "Enc PublicKey : %1").arg(getHexString(&binPubKey)));
        berApplet->log( QString( "Enc Output    : %1" ).arg( getHexString( &binOut )));
    }
    else {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

        JS_BIN_fileReadBER( mPriKeyPath->text().toLocal8Bit().toStdString().c_str(), &binPri );

        if( mUseKeyAlgCheck->isChecked() )
        {
            int nAlgType = JS_PKI_getPriKeyType( &binPri );
            berApplet->log( QString( "PriKey Type : %1").arg( getKeyTypeName( nAlgType )));

            if( nAlgType == JS_PKI_KEY_TYPE_RSA )
                mAlgCombo->setCurrentText( "RSA" );
            else if( nAlgType == JS_PKI_KEY_TYPE_SM2 )
                mAlgCombo->setCurrentText( "SM2" );
            else
            {
                berApplet->warningBox( tr( "Invalid private key algorithm"), this );
                goto end;
            }
        }

        if( mAlgCombo->currentText() == "RSA" )
            JS_PKI_RSADecryptWithPri( nVersion, &binSrc, &binPri, &binOut );
        else
            JS_PKI_SM2DecryptWithPri( &binSrc, &binPri, &binOut );

        berApplet->log( QString( "Algorithm      : %1").arg( mAlgCombo->currentText() ));
        berApplet->log( QString( "Dec Src        : %1").arg( getHexString(&binSrc)));
        berApplet->log( QString( "Dec PrivateKey : %1").arg(getHexString(&binPri)));
        berApplet->log( QString( "Dec Output     : %1" ).arg( getHexString( &binOut )));
    }

    if( mOutputTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_string( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_encodeHex( &binOut, &pOut );
    else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_encodeBase64( &binOut, &pOut );

    mOutputText->setPlainText(pOut);

end :
    repaint();

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

    if( strPath.length() < 1 )
        strPath = last_path_;

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.isEmpty() ) return;

    mCertPath->setText(fileName);
    last_path_ = fileName;

    repaint();
}

void PubEncDecDlg::findPrivateKey()
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

void PubEncDecDlg::changeValue()
{
//    QString strInput = mInputText->toPlainText();
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
//    mOutputText->setPlainText( "" );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    repaint();
}

void PubEncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void PubEncDecDlg::outputChanged()
{
    int nLen = getDataLen( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void PubEncDecDlg::algChanged()
{
    QString strAlg = mAlgCombo->currentText();

    if( strAlg == "RSA" )
        mVersionTypeCombo->setEnabled( true );
    else
        mVersionTypeCombo->setEnabled( false );
}

void PubEncDecDlg::clickPriKeyDecode()
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

void PubEncDecDlg::clickCertView()
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

void PubEncDecDlg::clickCertDecode()
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

void PubEncDecDlg::clickPriKeyType()
{
    BIN binPri = {0,0};
    QString strPath = mPriKeyPath->text();
    int nType = -1;

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binPri );

    nType = JS_PKI_getPriKeyType( &binPri );

    berApplet->messageBox( tr( "Private Key Type is %1").arg( getKeyTypeName( nType )), this);

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


void PubEncDecDlg::checkUseKeyAlg()
{
    bool bVal = mUseKeyAlgCheck->isChecked();

    mAlgCombo->setEnabled( !bVal );
}

void PubEncDecDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mPriKeyPath->clear();
    mCertPath->clear();
}
