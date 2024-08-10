#include <QDir>
#include <QDateTime>

#include "key_pair_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "ber_applet.h"
#include "common.h"
#include "cert_info_dlg.h"
#include "csr_info_dlg.h"
#include "settings_mgr.h"
#include "pri_key_info_dlg.h"

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

static QString kPrivateFile = "private.pem";
static QString kPublicFile = "public.pem";

KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mVersionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeVerison(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickGenKeyPair()));
    connect( mMakeCSRBtn, SIGNAL(clicked()), this, SLOT(clickMakeCSR()));

    connect( mPriViewBtn, SIGNAL(clicked()), this, SLOT(viewPriKey()));
    connect( mPubViewBtn, SIGNAL(clicked()), this, SLOT(viewPubKey()));

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mFindPubKeyBtn, SIGNAL(clicked()), this, SLOT(findPubKey()));
    connect( mFindEncPriKeyBtn, SIGNAL(clicked()), this, SLOT(findEncPriKey()));


    connect( mPriClearBtn, SIGNAL(clicked()), this, SLOT(clearPriKey()));
    connect( mPubClearBtn, SIGNAL(clicked()), this, SLOT(clearPubKey()));
    connect( mEncPriClearBtn, SIGNAL(clicked()), this, SLOT(clearEncPriKey()));
    connect( mPriInfoClearBtn, SIGNAL(clicked()), this, SLOT(clearPriInfo()));
    connect( mCSRClearBtn, SIGNAL(clicked()), this, SLOT(clearCSR()));

    connect( mPriDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPubDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePubKey()));
    connect( mEncPriDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeEncPriKey()));
    connect( mPriInfoDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriInfo()));
    connect( mCSRDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCSR()));

    connect( mPriTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPubTypeBtn, SIGNAL(clicked()), this, SLOT(typePubKey()));


    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mCSRViewBtn, SIGNAL(clicked()), this, SLOT(clickViewCSR()));

    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    tabList->layout()->setSpacing(5);
    tabTools->layout()->setSpacing(5);


    mPriViewBtn->setFixedWidth(34);
    mPubViewBtn->setFixedWidth(34);

    mPriClearBtn->setFixedWidth(34);
    mPriDecodeBtn->setFixedWidth(34);
    mPriTypeBtn->setFixedWidth(34);
    mPubClearBtn->setFixedWidth(34);
    mPubDecodeBtn->setFixedWidth(34);
    mPubTypeBtn->setFixedWidth(34);

    mEncPriClearBtn->setFixedWidth(34);
    mEncPriDecodeBtn->setFixedWidth(34);
    mPriInfoClearBtn->setFixedWidth(34);
    mPriInfoDecodeBtn->setFixedWidth(34);

    mCSRClearBtn->setFixedWidth(34);
    mCSRDecodeBtn->setFixedWidth(34);
#endif
    initUI();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mGenKeyPairBtn->setDefault(true);
}

KeyPairManDlg::~KeyPairManDlg()
{

}

void KeyPairManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif

    QStringList sTableLabels = { tr( "FolderName" ), tr( "Algorithm"), tr("Option") };

    mKeyPairTable->clear();
    mKeyPairTable->horizontalHeader()->setStretchLastSection(true);
    mKeyPairTable->setColumnCount( sTableLabels.size() );
    mKeyPairTable->setHorizontalHeaderLabels( sTableLabels );
    mKeyPairTable->verticalHeader()->setVisible(false);
    mKeyPairTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyPairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyPairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyPairTable->setColumnWidth( 0, nWidth * 5/10 );
    mKeyPairTable->setColumnWidth( 1, nWidth * 2/10 );
    mKeyPairTable->setColumnWidth( 2, nWidth * 3/10 );
}

void KeyPairManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void KeyPairManDlg::closeEvent(QCloseEvent *event )
{

}

void KeyPairManDlg::initialize()
{
    QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
    mSavePathText->setText( strKeyPairPath );

    mVersionCombo->addItems(kVersionList);

    loadKeyPairList();
}

void KeyPairManDlg::loadKeyPairList()
{
    int ret = 0;
    int row = 0;

    mKeyPairTable->setRowCount(0);

    QString strPath = berApplet->settingsMgr()->keyPairPath();
    QDir dir( strPath );

    for( const QFileInfo &folder: dir.entryInfoList(QDir::Dirs))
    {
        BIN binPri = {0,0};
        BIN binPub = {0,0};

        int nAlg = -1;
        int nOption = -1;

        const char *pAlg = NULL;
        const char *pGroup = NULL;

        if( folder.isFile() ) continue;

        QString strPubKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPublicFile );
        QFileInfo pubKeyFile( strPubKeyPath );
        QString strPriKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPrivateFile );
        QFileInfo priKeyFile( strPriKeyPath );

        QString strOption;

        if( pubKeyFile.exists() == false || priKeyFile.exists() == false ) continue;

        JS_BIN_fileReadBER( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPri );
        JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );

        JS_PKI_getPubKeyInfo( &binPub, &nAlg, &nOption );

        pAlg = JS_PKI_getKeyAlgName( nAlg );

        if( nAlg == JS_PKI_KEY_TYPE_ECC || nAlg == JS_PKI_KEY_TYPE_SM2 )
        {
            pGroup = JS_PKI_getSNFromNid( nOption );
            strOption = pGroup;
        }
        else
        {
            strOption = QString( "%1").arg( nOption );
        }


        mKeyPairTable->insertRow(row);
        mKeyPairTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( folder.baseName() );

        mKeyPairTable->setItem( row, 0, item );
        mKeyPairTable->setItem( row, 1, new QTableWidgetItem(QString("%1").arg( pAlg)));
        mKeyPairTable->setItem( row, 2, new QTableWidgetItem( QString("%1" ).arg( strOption )));

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        row++;
    }
}

const QString KeyPairManDlg::getTypePathName( qint64 now_t, DerType nType )
{
    QString strFullName;

    QDateTime dateTime;
    dateTime.setSecsSinceEpoch( now_t );

    QString strDateTime = dateTime.toString( "yyyyMMddHHmmss" );
    QString strName;
    QString strExt;

    QFileInfo priKeyInfo( mPriPathText->text() );

    if( mSavePEMCheck->isChecked() )
        strExt = "pem";
    else
        strExt = "der";

    if( nType == TypePriKey )
        strName = "private_key";
    else if( nType == TypePubKey )
        strName = "public_key";
    else if( nType == TypeEncPri )
        strName = QString( "enc_%1" ).arg( priKeyInfo.baseName() );
    else if( nType == TypePriInfo )
        strName = QString( "info_%1" ).arg( priKeyInfo.baseName() );
    else if( nType == TypeCSR )
        strName = QString( "csr_%1" ).arg( priKeyInfo.baseName() );


    if( mSavePathText->text().length() > 0 )
        strFullName = mSavePathText->text();
    else
        strFullName = ".";

    strFullName += QString( "/%1_%2.%3" ).arg( strName ).arg( strDateTime ).arg(strExt);

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

int KeyPairManDlg::Save( qint64 tTime, DerType nType, const QString strHex )
{
    int ret = 0;
    BIN binData = {0,0};
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    ret = Save( tTime, nType, &binData );
    JS_BIN_reset( &binData );
    return ret;
}

int KeyPairManDlg::Save( qint64 tTime, DerType nType, const BIN *pBin )
{
    QString strPath = getTypePathName( tTime, nType );

    if( mSavePEMCheck->isChecked() == true )
    {
        int nPEMType = 0;

        if( nType == TypePriKey )
        {
            nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
        }
        else if( nType == TypePubKey )
        {
            nPEMType = JS_PEM_TYPE_PUBLIC_KEY;
        }
        else if( nType == TypeEncPri )
        {
            nPEMType = JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;
        }
        else if( nType == TypePriInfo )
        {
            nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
        }
        else if( nType == TypeCSR )
        {
            nPEMType = JS_PEM_TYPE_CSR;
        }

        JS_BIN_writePEM( pBin, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
    }
    else
    {
        JS_BIN_fileWrite( pBin, strPath.toLocal8Bit().toStdString().c_str() );
    }

    if( nType == TypePriKey )
    {
        mPriPathText->setText( strPath );
    }
    else if( nType == TypePubKey )
    {
        mPubPathText->setText( strPath );
    }
    else if( nType == TypeEncPri )
    {
        mEncPriPathText->setText( strPath );
    }
    else if( nType == TypePriInfo )
    {
        mPriInfoPathText->setText( strPath );
    }
    else if( nType == TypeCSR )
    {
        mCSRPathText->setText( strPath );
    }

    return 0;
}

void KeyPairManDlg::clickGenKeyPair()
{
    QDir dir;
    QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
    GenKeyPairDlg genKeyPair;

    if( genKeyPair.exec() == QDialog::Accepted )
    {
        BIN binPri = {0,0};
        BIN binPub = {0,0};

        QString strName = genKeyPair.mNameText->text();

        QString fullPath = QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName );
        if( dir.exists( fullPath ) )
        {
            berApplet->warningBox( tr( "The folder(%1) is already existed" ).arg( strName ), this );
            return;
        }
        else
        {
            dir.mkdir( fullPath );
        }

        QString strPriPath = QString( "%1/%2" ).arg( fullPath ).arg( kPrivateFile );
        QString strPubPath = QString( "%1/%2" ).arg( fullPath ).arg( kPublicFile );

        JS_BIN_decodeHex( genKeyPair.getPriKeyHex().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( genKeyPair.getPubKeyHex().toStdString().c_str(), &binPub );

        JS_BIN_writePEM( &binPri, JS_PEM_TYPE_PRIVATE_KEY, strPriPath.toLocal8Bit().toStdString().c_str() );
        JS_BIN_writePEM( &binPub, JS_PEM_TYPE_PUBLIC_KEY, strPubPath.toLocal8Bit().toStdString().c_str() );

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        loadKeyPairList();

        berApplet->messageLog( tr( "Key pair generation was successful"), this );
    }
}

void KeyPairManDlg::clickMakeCSR()
{
    BIN binData = {0,0};
    QString strFile = mPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    MakeCSRDlg makeCSR;
    makeCSR.setPriKey( &binData );

    if( makeCSR.exec() == QDialog::Accepted )
    {
        time_t now_t = time(NULL);

        QString strCSRHex = makeCSR.getCSRHex();
        Save( now_t, TypeCSR, strCSRHex );
    }

    JS_BIN_reset( &binData );
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
        berApplet->warningBox( tr( "find public key or certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );
    if( ret == JSR_VALID )
        berApplet->messageBox( tr("The private key and the public key are correct"), this );
    else
        berApplet->warningBox( QString( tr("The private key and the public key are incorrect [%1]")).arg(ret), this );

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

    time_t now_t = time(NULL);

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find private key" ), this );
        return;
    }

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
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

    Save( now_t, TypePriInfo, &binInfo );
    Save( now_t, TypeEncPri, &binEnc );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binEnc );
}


void KeyPairManDlg::clickViewCSR()
{
    CSRInfoDlg csrInfo;

    BIN binData = {0,0};
    QString strFile = mCSRPathText->text();

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

    time_t now_t = time(NULL);

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find encrypted private key" ), this );
        return;
    }

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mPasswdText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg(ret), this);
        goto end;
    }

    Save( now_t, TypePriKey, &binDec );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );
}

void KeyPairManDlg::clickClearAll()
{
    clearPriKey();
    clearPubKey();
    clearEncPriKey();
    clearPriInfo();
    clearCSR();
}

void KeyPairManDlg::viewPriKey()
{
    BIN binPriKey = { 0,0 };
    PriKeyInfoDlg priKeyInfo;
    QString strPriPath = mPriPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPriKey );

    priKeyInfo.setPrivateKey( &binPriKey );
    priKeyInfo.exec();

    JS_BIN_reset( &binPriKey );
}

void KeyPairManDlg::viewPubKey()
{
    BIN binPubKey = {0,0};
    PriKeyInfoDlg priKeyInfo;
    QString strPubPath = mPubPathText->text();

    if( strPubPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a public key"), this );
        return;
    }

    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPubKey );

    priKeyInfo.setPublicKey( &binPubKey );
    priKeyInfo.exec();

    JS_BIN_reset( &binPubKey );
}

void KeyPairManDlg::findPriKey()
{
    QString strPath = mPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->settingsMgr()->tempCertPath();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriPathText->setText( filePath );
}

void KeyPairManDlg::findPubKey()
{
    QString strPath = mPubPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->settingsMgr()->tempCertPath();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPubPathText->setText( filePath );
}

void KeyPairManDlg::findEncPriKey()
{
    QString strPath = mEncPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->settingsMgr()->tempCertPath();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mEncPriPathText->setText( filePath );
}

void KeyPairManDlg::clearPriKey()
{
    mPriPathText->clear();
}

void KeyPairManDlg::clearPubKey()
{
    mPubPathText->clear();
}

void KeyPairManDlg::clearEncPriKey()
{
    mEncPriPathText->clear();
}

void KeyPairManDlg::clearPriInfo()
{
    mPriInfoPathText->clear();
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

    nType = JS_PKI_getPubKeyType( &binData );
    berApplet->messageBox( tr( "The public key type is %1").arg( getKeyTypeName( nType )), this);

    JS_BIN_reset( &binData );
}

