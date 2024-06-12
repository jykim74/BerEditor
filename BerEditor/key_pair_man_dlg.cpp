#include <QDir>
#include <QDateTime>

#include "key_pair_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "ber_applet.h"
#include "common.h"
#include "cert_info_dlg.h"
#include "csr_info_dlg.h"

#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "js_pki_key.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_error.h"

static QStringList kVersionList = { "V1", "V2" };
static QStringList kPBEv1List = { "PBE-SHA1-3DES", "PBE-SHA1-2DES" };
static QStringList kPBEv2List = { "AES-128-CBC", "AES-256-CBC", "ARIA-128-CBC", "ARIA-256-CBC" };


KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mVersionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeVerison(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickGenKeyPair()));
    connect( mMakeCSRBtn, SIGNAL(clicked()), this, SLOT(clickMakeCSR()));

    connect( mFindSavePathBtn, SIGNAL(clicked()), this, SLOT(findSavePath()));
    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mFindPubKeyBtn, SIGNAL(clicked()), this, SLOT(findPubKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindEncPriKeyBtn, SIGNAL(clicked()), this, SLOT(findEncPriKey()));
    connect( mFindPFXBtn, SIGNAL(clicked()), this, SLOT(findPFX()));

    connect( mPriClearBtn, SIGNAL(clicked()), this, SLOT(clearPriKey()));
    connect( mPubClearBtn, SIGNAL(clicked()), this, SLOT(clearPubKey()));
    connect( mCertClearBtn, SIGNAL(clicked()), this, SLOT(clearCert()));
    connect( mEncPriClearBtn, SIGNAL(clicked()), this, SLOT(clearEncPriKey()));
    connect( mPriInfoClearBtn, SIGNAL(clicked()), this, SLOT(clearPriInfo()));
    connect( mPFXClearBtn, SIGNAL(clicked()), this, SLOT(clearPFX()));
    connect( mCSRClearBtn, SIGNAL(clicked()), this, SLOT(clearCSR()));

    connect( mPriDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPubDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePubKey()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mEncPriDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeEncPriKey()));
    connect( mPriInfoDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriInfo()));
    connect( mPFXDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePFX()));
    connect( mCSRDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCSR()));

    connect( mPriTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPubTypeBtn, SIGNAL(clicked()), this, SLOT(typePubKey()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mEncryptPFXBtn, SIGNAL(clicked()), this, SLOT(clickEncryptPFX()));
    connect( mViewCertBtn, SIGNAL(clicked()), this, SLOT(clickViewCert()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mDecryptPFXBtn, SIGNAL(clicked()), this, SLOT(clickDecryptPFX()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mPriClearBtn->setFixedWidth(34);
    mPriDecodeBtn->setFixedWidth(34);
    mPriTypeBtn->setFixedWidth(34);
    mPubClearBtn->setFixedWidth(34);
    mPubDecodeBtn->setFixedWidth(34);
    mPubTypeBtn->setFixedWidth(34);
    mCertClearBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);

    mEncPriClearBtn->setFixedWidth(34);
    mEncPriDecodeBtn->setFixedWidth(34);
    mPriInfoClearBtn->setFixedWidth(34);
    mPriInfoDecodeBtn->setFixedWidth(34);
    mPFXClearBtn->setFixedWidth(34);
    mPFXDecodeBtn->setFixedWidth(34);
    mCSRClearBtn->setFixedWidth(34);
    mCSRDecodeBtn->setFixedWidth(34);
#endif

    initialize();
}

KeyPairManDlg::~KeyPairManDlg()
{

}

void KeyPairManDlg::initialize()
{
    mVersionCombo->addItems(kVersionList);
}

const QString KeyPairManDlg::getTypePathName( qint64 now_t, DerType nType )
{
    QString strFullName;

    QDateTime dateTime;
    dateTime.setSecsSinceEpoch( now_t );

    QString strDateTime = dateTime.toString( "yyyyMMddHHmmss" );
    QString strName;

    if( nType == TypePriKey )
        strName = "private_key";
    else if( nType == TypePubKey )
        strName = "public_key";
    else if( nType == TypeCert )
        strName = "cert";
    else if( nType == TypeEncPri )
        strName = "enc_private_key";
    else if( nType == TypePriInfo )
        strName = "private_key_info";
    else if( nType == TypePFX )
        strName = "pfx";
    else if( nType == TypeCSR )
        strName = "csr";

    strFullName = mSavePathText->text();
    strFullName += QString( "/%1_%2.pem" ).arg( strName ).arg( strDateTime );

    return strFullName;
}

void KeyPairManDlg::changeVerison( int index )
{
    mModeCombo->clear();

    if( index == 0 )
        mModeCombo->addItems( kPBEv1List );
    else
        mModeCombo->addItems( kPBEv2List );
}

void KeyPairManDlg::clickGenKeyPair()
{
    GenKeyPairDlg genKeyPair;
    if( genKeyPair.exec() == QDialog::Accepted )
    {
        time_t now_t = time(NULL);

        BIN binPub = {0,0};
        BIN binPri = {0,0};

        QString strPriHex = genKeyPair.getPriKeyHex();
        QString strPubHex = genKeyPair.getPubKeyHex();

        QString strPriPath = getTypePathName( now_t, TypePriKey);
        QString strPubPath = getTypePathName( now_t, TypePubKey );

        JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( strPubHex.toStdString().c_str(), &binPub );

        JS_BIN_fileWrite( &binPub, strPubPath.toLocal8Bit().toStdString().c_str() );
        JS_BIN_fileWrite( &binPri, strPriPath.toLocal8Bit().toStdString().c_str() );

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        mPriPathText->setText( strPriPath );
        mPubPathText->setText( strPubPath );
    }
}

void KeyPairManDlg::clickMakeCSR()
{
    MakeCSRDlg makeCSR;
    if( makeCSR.exec() == QDialog::Accepted )
    {
        time_t now_t = time(NULL);

        BIN binCSR = {0,0};
        QString strCSRHex = makeCSR.getCSRHex();
        QString strCSRPath = getTypePathName( now_t, TypeCSR );

        JS_BIN_decodeHex( strCSRHex.toStdString().c_str(), &binCSR );
        JS_BIN_fileWrite( &binCSR, strCSRPath.toLocal8Bit().toStdString().c_str() );
        JS_BIN_reset( &binCSR );

        mCSRPathText->setText( strCSRPath );
    }
}

void KeyPairManDlg::clickCheckKeyPair()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    QString strPriPath = mPriPathText->text();
    QString strPubPath = mPubPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find private key"), this );
        return;
    }

    if( strPubPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find public key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );
    if( ret == JSR_VALID )
        berApplet->messageBox( tr("The keypair is correct"), this );
    else
        berApplet->warningBox( QString( tr("The keypair is incorrect [%1]")).arg(ret), this );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void KeyPairManDlg::clickEncrypt()
{
    int ret = 0;
    int nPBE = 0;
    int nKeyType = -1;
    BIN binData = {0,0};
    BIN binInfo = {0,0};
    BIN binEnc = {0,0};
    QString strFile = mPriPathText->text();
    QString strSN = mModeCombo->currentText();
    QString strPasswd = mPasswdText->text();

    QString strPriInfoPath;
    QString strEncPriPath;

    time_t now_t = time(NULL);

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    nPBE = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
    nKeyType = JS_PKI_getPriKeyType( &binData );

    ret = JS_PKI_encryptPrivateKey( nKeyType, nPBE, strPasswd.toStdString().c_str(), &binData, &binInfo, &binEnc );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to encrypt private key: %1").arg(ret), this);
        goto end;
    }

    strPriInfoPath = getTypePathName( now_t, TypePriInfo );
    strEncPriPath = getTypePathName( now_t, TypeEncPri );

    JS_BIN_fileWrite( &binInfo, strPriInfoPath.toLocal8Bit().toStdString().c_str() );
    JS_BIN_fileWrite( &binEnc, strEncPriPath.toLocal8Bit().toStdString().c_str() );

    mPriInfoPathText->setText( strPriInfoPath );
    mEncPriPathText->setText( strEncPriPath );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binEnc );
}

void KeyPairManDlg::clickEncryptPFX()
{
    int ret = 0;

    int nPBE = 0;
    int nKeyType = -1;

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binPFX = {0,0};

    QString strPriPath = mPriPathText->text();
    QString strCertPath = mCertPathText->text();

    QString strSN = mModeCombo->currentText();
    QString strPasswd = mPasswdText->text();

    QString strPFXPath;

    time_t now_t = time(NULL);

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find private key"), this );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );

    nPBE = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
    nKeyType = JS_PKI_getPriKeyType( &binPri );

    ret = JS_PKI_encodePFX( &binPFX, nKeyType, strPasswd.toStdString().c_str(), nPBE, &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to make PFX: %1").arg(ret), this);
        goto end;
    }

    strPFXPath = getTypePathName( now_t, TypePFX );
    JS_BIN_fileWrite( &binPFX, strPFXPath.toLocal8Bit().toStdString().c_str() );
    mPFXPathText->setText( strPFXPath );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPFX );
}

void KeyPairManDlg::clickViewCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::clickViewCSR()
{
    CSRInfoDlg csrInfo;

    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find CSR" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    csrInfo.setReqBIN( &binData );
    csrInfo.exec();

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::clickDecrypt()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binInfo = {0,0};
    BIN binDec = {0,0};
    QString strFile = mEncPriPathText->text();
    QString strPasswd = mPasswdText->text();
    QString strPriPath;

    time_t now_t = time(NULL);

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find encrypted private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg(ret), this);
        goto end;
    }

    strPriPath = getTypePathName( now_t, TypeEncPri );
    JS_BIN_fileWrite( &binDec, strPriPath.toLocal8Bit().toStdString().c_str() );
    mPriPathText->setText( strPriPath );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );
}

void KeyPairManDlg::clickDecryptPFX()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};

    QString strFile = mPFXPathText->text();
    QString strPasswd = mPasswdText->text();

    QString strPriPath;
    QString strCertPath;

    time_t now_t = time(NULL);

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find PFX" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    ret = JS_PKI_decodePFX( &binData, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg(ret), this);
        goto end;
    }

    strPriPath = getTypePathName( now_t, TypePriKey );
    strCertPath = getTypePathName( now_t, TypeCert );
    JS_BIN_fileWrite( &binPri, strPriPath.toLocal8Bit().toStdString().c_str() );
    JS_BIN_fileWrite( &binCert, strCertPath.toLocal8Bit().toStdString().c_str() );
    mPriPathText->setText( strPriPath );
    mCertPathText->setText( strCertPath );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void KeyPairManDlg::clickClearAll()
{
    clearPriKey();
    clearPubKey();
    clearCert();
    clearEncPriKey();
    clearPriInfo();
    clearPFX();
    clearCSR();
}

void KeyPairManDlg::findSavePath()
{
    QString strPath = mSavePathText->text();

    if( strPath.length() < 1 )
    {
        strPath = QDir::homePath();
    }

    QString folderPath = findFolder( this, strPath );
    if( folderPath.length() > 0 )
        mSavePathText->setText( folderPath );
}

void KeyPairManDlg::findPriKey()
{
    QString strPath = mPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriPathText->setText( filePath );
}

void KeyPairManDlg::findPubKey()
{
    QString strPath = mPubPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPubPathText->setText( filePath );
}

void KeyPairManDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void KeyPairManDlg::findEncPriKey()
{
    QString strPath = mEncPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mEncPriPathText->setText( filePath );
}

void KeyPairManDlg::findPFX()
{
    QString strPath = mPFXPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPFXPathText->setText( filePath );
}

void KeyPairManDlg::clearPriKey()
{
    mPriPathText->clear();
}

void KeyPairManDlg::clearPubKey()
{
    mPubPathText->clear();
}

void KeyPairManDlg::clearCert()
{
    mCertPathText->clear();
}

void KeyPairManDlg::clearEncPriKey()
{
    mEncPriPathText->clear();
}

void KeyPairManDlg::clearPriInfo()
{
    mPriInfoPathText->clear();
}

void KeyPairManDlg::clearPFX()
{
    mPFXPathText->clear();
}

void KeyPairManDlg::clearCSR()
{
    mCSRPathText->clear();
}

void KeyPairManDlg::decodePriKey()
{
    BIN binData = {0,0};
    QString strFile = mPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodePubKey()
{
    BIN binData = {0,0};
    QString strFile = mPubPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Public Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodeCert()
{
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodeEncPriKey()
{
    BIN binData = {0,0};
    QString strFile = mEncPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Encrypted Private Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodePriInfo()
{
    BIN binData = {0,0};
    QString strFile = mPriInfoPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no private key information" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodePFX()
{
    BIN binData = {0,0};
    QString strFile = mPFXPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find PFX" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodeCSR()
{
    BIN binData = {0,0};
    QString strFile = mCSRPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find CSR" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::typePriKey()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The private key type is %1").arg( getKeyTypeName( nType )), this);

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::typePubKey()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mPubPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Public Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The public key type is %1").arg( getKeyTypeName( nType )), this);

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}
