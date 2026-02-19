#include <QDir>
#include <QDateTime>
#include <QMenu>

#include "key_pair_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "csr_info_dlg.h"
#include "settings_mgr.h"
#include "pri_key_info_dlg.h"
#include "new_passwd_dlg.h"
#include "passwd_dlg.h"
#include "name_dlg.h"
#include "export_dlg.h"

#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_tools.h"
#include "js_pki_key.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_error.h"
#include "js_pqc.h"


static QString sKeyTypeAll = "ALL";

static QStringList kKeyTypeList = {
    sKeyTypeAll, JS_PKI_KEY_NAME_RSA, JS_PKI_KEY_NAME_ECDSA, JS_PKI_KEY_NAME_DSA,
    JS_PKI_KEY_NAME_SM2, JS_PKI_KEY_NAME_EDDSA
};

static QStringList kPQCKeyTypeList = {
    JS_PKI_KEY_NAME_ML_KEM, JS_PKI_KEY_NAME_ML_DSA, JS_PKI_KEY_NAME_SLH_DSA
};



KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    mode_ = 0;
    load_keypair_ = false;
    is_pqc_ = true;

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    connect( mKeyPairTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mLGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickLGenKeyPair()));
    connect( mLDeleteBtn, SIGNAL(clicked()), this, SLOT(clickLDelete()));
    connect( mLRenameBtn, SIGNAL(clicked()), this, SLOT(clickLRename()));
    connect( mLMakeCSRBtn, SIGNAL(clicked()), this, SLOT(clickLMakeCSR()));
    connect( mLViewPriKeyBtn, SIGNAL(clicked()), this, SLOT(clickLViewPriKey()));
    connect( mLViewPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickLViewPubKey()));
    connect( mLDecodePriKeyBtn, SIGNAL(clicked()), this, SLOT(clickLDecodePriKey()));
    connect( mLDecodePubKeyBtn, SIGNAL(clicked()), this, SLOT(clickLDecodePubKey()));

    connect( mLRunSignBtn, SIGNAL(clicked()), this, SLOT(clickLRunSign()));
    connect( mLRunVerifyBtn, SIGNAL(clicked()), this, SLOT(clickLRunVerify()));
    connect( mLRunPubEncBtn, SIGNAL(clicked()), this, SLOT(clickLRunPubEnc()));
    connect( mLRunPubDecBtn, SIGNAL(clicked()), this, SLOT(clickLRunPubDec()));

    connect( mSaveToListBtn, SIGNAL(clicked()), this, SLOT(clickSaveToList()));
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



    connect( mImportBtn, SIGNAL(clicked()), this, SLOT(clickImport()));
    connect( mExportBtn, SIGNAL(clicked()), this, SLOT(clickExport()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    tabList->layout()->setSpacing(5);
    tabList->layout()->setMargin(5);
    tabTools->layout()->setSpacing(5);
    tabTools->layout()->setMargin(5);

    mListManGroup->layout()->setMargin(5);
    mListManGroup->layout()->setSpacing(5);

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

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mCloseBtn->setDefault(true);
}

KeyPairManDlg::~KeyPairManDlg()
{

}

void KeyPairManDlg::setMode( int nMode )
{
    mode_ = nMode;

    if( mode_ == KeyPairModeSelect )
    {
        connect( mKeyPairTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));

        mModeLabel->setText( tr("Select") );
        setGroupHide( true );
        mTabWidget->setTabEnabled( 1, false );
        mOKBtn->show();
    }
    else
    {
        connect( mKeyPairTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickLViewPriKey()));

        mModeLabel->setText( tr("Manage") );
        setGroupHide( false );
        mTabWidget->setTabEnabled( 1, true );
        mOKBtn->hide();
    }
}

void KeyPairManDlg::setPQCEnable( bool bVal )
{
    is_pqc_ = bVal;

    mKeyTypeCombo->clear();
    mKeyTypeCombo->addItems( kKeyTypeList );

    if( bVal == true ) mKeyTypeCombo->addItems( kPQCKeyTypeList );
}

void KeyPairManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void KeyPairManDlg::setKeyAlg( const QString strKeyAlg )
{
    mKeyTypeCombo->setCurrentText( strKeyAlg );
}

void KeyPairManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 8/10;
#else
    int nWidth = width() * 8/10;
#endif
    mKeyTypeCombo->addItems( kKeyTypeList );
    mKeyTypeCombo->addItems( kPQCKeyTypeList );

    mCheckKeyPairBtn->setToolTip( tr( "Check if the private key and public key pair are correct" ) );
    mSaveToListBtn->setToolTip( tr( "Store private and public keys in the key pair list" ));
    mMakeCSRBtn->setToolTip( tr( "Create a CSR for your private key file" ) );
    mEncryptBtn->setToolTip( tr( "Encrypt your private key file" ));
    mDecryptBtn->setToolTip( tr( "Decrypting an encrypted private key" ));

    QStringList sTableLabels = { tr( "FolderName" ), tr( "ALG"), tr("Option"), tr("LastModified") };

    mKeyPairTable->clear();
    mKeyPairTable->horizontalHeader()->setStretchLastSection(true);
    mKeyPairTable->setColumnCount( sTableLabels.size() );
    mKeyPairTable->setHorizontalHeaderLabels( sTableLabels );
    mKeyPairTable->verticalHeader()->setVisible(false);
    mKeyPairTable->setStyleSheet( kSelectStyle );
    mKeyPairTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyPairTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mKeyPairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyPairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyPairTable->setColumnWidth( 0, nWidth * 4/10 );
    mKeyPairTable->setColumnWidth( 1, nWidth * 2/10 );
    mKeyPairTable->setColumnWidth( 2, nWidth * 2/10 );

    mPriPathText->setPlaceholderText( tr("Find a private key") );
    mPubPathText->setPlaceholderText( tr( "Find a public key" ) );
    mEncPriPathText->setPlaceholderText( tr( "Find a encrypted private key" ));
    mPriInfoPathText->setPlaceholderText( tr( "Private key information file path") );
    mCSRPathText->setPlaceholderText( tr( "CSR file path") );


    mOKBtn->hide();
}

void KeyPairManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void KeyPairManDlg::closeEvent(QCloseEvent *event )
{

}

void KeyPairManDlg::keyTypeChanged( int index )
{
    loadKeyPairList();
}

void KeyPairManDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *decodePubKeyAct = new QAction( tr( "Decode PubKey" ), this );
    QAction *makeCSRAct = new QAction( tr( "Make CSR" ), this );
    QAction *viewPubKeyAct = new QAction( tr( "View PubKey" ), this );
    QAction *decodePriKeyAct = new QAction( tr( "Decode PriKey" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );
    QAction *renameAct = new QAction( tr("Rename" ), this );
    QAction *viewPriKeyAct = new QAction( tr( "View PriKey" ), this );
    QAction *exportAct = new QAction( tr("Export"), this );

    connect( decodePubKeyAct, SIGNAL(triggered()), this, SLOT(clickLDecodePubKey()));
    connect( makeCSRAct, SIGNAL(triggered()), this, SLOT(clickLMakeCSR()));
    connect( viewPubKeyAct, SIGNAL(triggered()), this, SLOT(clickLViewPubKey()));
    connect( decodePriKeyAct, SIGNAL(triggered()), this, SLOT(clickLDecodePriKey()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickLDelete()));
    connect( renameAct, SIGNAL(triggered(bool)), this, SLOT(clickLRename()));
    connect( viewPriKeyAct, SIGNAL(triggered()), this, SLOT(clickLViewPriKey()));
    connect( exportAct, SIGNAL(triggered()), this, SLOT(clickExport()));

    menu->addAction( decodePubKeyAct );
    menu->addAction( makeCSRAct );
    menu->addAction( viewPubKeyAct );
    menu->addAction( decodePriKeyAct );
    menu->addAction( deleteAct );
    menu->addAction( renameAct );
    menu->addAction( viewPriKeyAct );
    menu->addAction( exportAct );

    menu->popup( mKeyPairTable->viewport()->mapToGlobal(pos));
}

void KeyPairManDlg::initialize()
{
    mTabWidget->setCurrentIndex(0);

    QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
    mSavePathText->setText( strKeyPairPath );

    mModeCombo->addItems( kPBEList );
    mModeCombo->setCurrentText( berApplet->settingsMgr()->priEncMethod());

    if( load_keypair_ == false )
        loadKeyPairList();
}

void KeyPairManDlg::setGroupHide( bool bHide )
{
    if( bHide == true )
        mListManGroup->hide();
    else
        mListManGroup->show();
}

const QString KeyPairManDlg::getSelectedPath()
{
    QString strPath;

    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem* item = mKeyPairTable->item( idx.row(), 0 );

    if( item ) strPath = item->data(Qt::UserRole).toString();

    return strPath;
}

void KeyPairManDlg:: loadKeyPairList()
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

        const char *pGroup = NULL;

        if( folder.isFile() ) continue;

        QDateTime date = folder.lastModified();

        QString strPubKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPublicFile );
        QFileInfo pubKeyFile( strPubKeyPath );
        QString strPriKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPrivateFile );
        QFileInfo priKeyFile( strPriKeyPath );

        QString strOption;
        QString strAlg;
        QString strKeyType = mKeyTypeCombo->currentText();

        if( pubKeyFile.exists() == false || priKeyFile.exists() == false ) continue;

        JS_BIN_fileReadBER( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPri );
        JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );

        JS_PKI_getPubKeyInfo( &binPub, &nAlg, &nOption );
        if( strKeyType == JS_PKI_KEY_NAME_RSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_RSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ECDSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_ECDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SM2 )
        {
            if( nAlg != JS_PKI_KEY_TYPE_SM2 )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_DSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_DSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_EDDSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_EDDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_KEM )
        {
            if( nAlg != JS_PKI_KEY_TYPE_ML_KEM )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_DSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_ML_DSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SLH_DSA )
        {
            if( nAlg != JS_PKI_KEY_TYPE_SLH_DSA )
                continue;
        }
        else // ALL case
        {
            if( is_pqc_ == false )
            {
                if( nAlg == JS_PKI_KEY_TYPE_ML_DSA || nAlg == JS_PKI_KEY_TYPE_SLH_DSA || nAlg == JS_PKI_KEY_TYPE_ML_KEM )
                    continue;
            }
        }

        strAlg = JS_PKI_getKeyAlgName( nAlg );

        if( nAlg == JS_PKI_KEY_TYPE_ECDSA || nAlg == JS_PKI_KEY_TYPE_SM2 )
        {
            pGroup = JS_PKI_getSNFromNid( nOption );
            strOption = pGroup;
        }
        else if( nAlg == JS_PKI_KEY_TYPE_EDDSA )
        {
            strOption = JS_RAW_getParamName( nOption );
        }
        else if( nAlg == JS_PKI_KEY_TYPE_ML_KEM || nAlg == JS_PKI_KEY_TYPE_ML_DSA || nAlg == JS_PKI_KEY_TYPE_SLH_DSA )
        {
            strOption = JS_RAW_getParamName( nOption );
        }
        else
        {
            strOption = QString( "%1").arg( nOption );
        }


        mKeyPairTable->insertRow(0);
        mKeyPairTable->setRowHeight( 0, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( folder.baseName() );
        item->setIcon(QIcon(":/images/keypair2.png" ));

        item->setData(Qt::UserRole, folder.filePath() );

        mKeyPairTable->setItem( 0, 0, item );
        mKeyPairTable->setItem( 0, 1, new QTableWidgetItem(QString("%1").arg( strAlg)));
        mKeyPairTable->setItem( 0, 2, new QTableWidgetItem( QString("%1" ).arg( strOption )));
        mKeyPairTable->setItem( 0, 3, new QTableWidgetItem(QString("%1").arg( date.toString("yy-MM-dd HH:mm") )));

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        row++;
    }

    load_keypair_ = true;
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

    if( mSaveDERCheck->isChecked() )
        strExt = "der";
    else
        strExt = "pem";

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

    strFullName = berApplet->curPath();
    strFullName += QString( "/%1_%2.%3" ).arg( strName ).arg( strDateTime ).arg(strExt);

    return strFullName;
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
    int ret = -1;
    QString strPath = getTypePathName( tTime, nType );

    if( mSaveDERCheck->isChecked() == true )
    {
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

        ret = JS_BIN_fileWrite( pBin, strPath.toLocal8Bit().toStdString().c_str() );
    }
    else
    {
        int nPEMType = 0;

        if( nType == TypePriKey )
        {
            nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
            ret = writePriKeyPEM( pBin, strPath );
            mPriPathText->setText( strPath );
        }
        else if( nType == TypePubKey )
        {
            nPEMType = JS_PEM_TYPE_PUBLIC_KEY;
            ret = writePubKeyPEM( pBin, strPath );
            mPubPathText->setText( strPath );
        }
        else if( nType == TypeEncPri )
        {
            nPEMType = JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;
            mEncPriPathText->setText( strPath );
            ret = JS_BIN_writePEM( pBin, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
        }
        else if( nType == TypePriInfo )
        {
            nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
            mPriInfoPathText->setText( strPath );
            ret = JS_BIN_writePEM( pBin, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
        }
        else if( nType == TypeCSR )
        {
            nPEMType = JS_PEM_TYPE_CSR;
            mCSRPathText->setText( strPath );
            ret = JS_BIN_writePEM( pBin, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
        }
    }

    return ret;
}

void KeyPairManDlg::clickLGenKeyPair()
{
    int ret = 0;
    QDir dir;
    QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
    GenKeyPairDlg genKeyPair;
    QString strName;
    QString fullPath;

    BIN binPri = {0,0};
    BIN binPub = {0,0};


    if( genKeyPair.exec() == QDialog::Accepted )
    {
        strName = genKeyPair.mNameText->text();


        if( dir.exists( QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName ) ) )
        {
            for( int i = 2; i < 100; i++ )
            {
                if( dir.exists( QString( "%1/%2 (%3)").arg( strKeyPairPath ).arg( strName ).arg(i) ) )
                {
                    continue;
                }
                else
                {
                    strName = QString( "%1 (%2)" ).arg( strName ).arg( i );
                    break;
                }
            }

            if( dir.exists( QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName ) ))
            {
                berApplet->warningBox( tr( "The folder(%1) is already existed" ).arg( strName ), this );
                return;
            }
        }

        fullPath = QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName );

        if( dir.mkdir( fullPath ) == false )
        {
            berApplet->warningBox( tr( "failed to make a folder" ), this );
            return;
        }

        QString strPriPath = QString( "%1/%2" ).arg( fullPath ).arg( kPrivateFile );
        QString strPubPath = QString( "%1/%2" ).arg( fullPath ).arg( kPublicFile );

        JS_BIN_decodeHex( genKeyPair.getPriKeyHex().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( genKeyPair.getPubKeyHex().toStdString().c_str(), &binPub );

        ret = writePubKeyPEM( &binPub, strPubPath );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to write public key: %1" ).arg(JERR(ret)), this );
            dir.rmpath( fullPath );
            goto end;
        }

        ret = writePriKeyPEM( &binPri, strPriPath );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to write private key: %1" ).arg(JERR(ret)), this );
            dir.remove( strPriPath );
            dir.rmpath( fullPath );
            goto end;
        }

        loadKeyPairList();
        berApplet->messageLog( tr( "%1 key pair was successfully generated").arg( strName ), this );
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void KeyPairManDlg::clickLDelete()
{
    int ret = 0;


    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();
    QDir dir;

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure to delete the keypair" ), this, false );
    if( bVal == false ) return;

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    bool bPub = dir.remove( strPubKeyPath );
    bool bPri = dir.remove( strPriKeyPath );

    if( dir.rmdir( strPath ) == false )
    {
        berApplet->warningBox( tr( "fail to delete[%1:%2]" ).arg( bPub ).arg( bPri ), this );
        return;
    }

    loadKeyPairList();
}

void KeyPairManDlg::clickLRename()
{
    int ret = 0;

    QString strPath = getSelectedPath();
    QString strNewPath;

    QDir dir;

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    QFileInfo pathInfo(strPath);
    QString strBaseName = pathInfo.baseName();

    NameDlg nameDlg;

    nameDlg.setHeadLabel( tr("Enter the name you want to change") );
    nameDlg.setName( strBaseName );

    if( nameDlg.exec() != QDialog::Accepted )
    {
        return;
    }

    strNewPath = QString( "%1/%2")
                     .arg( berApplet->settingsMgr()->keyPairPath() )
                     .arg( nameDlg.mNameText->text() );

    if( dir.rename( strPath, strNewPath ) == false )
    {
        berApplet->warningBox( tr( "fail to rename" ), this );
        return;
    }

    loadKeyPairList();
}

void KeyPairManDlg::clickLMakeCSR()
{
    int ret = 0;
    QDir dir;

    BIN binPri = {0,0};
    BIN binCSR = {0,0};

    QString strPubKeyPath;
    QString strPriKeyPath;

    QString strPath;

    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem* item = mKeyPairTable->item( idx.row(), 0 );
    QTableWidgetItem* item1 = mKeyPairTable->item( idx.row(), 1 );
    QTableWidgetItem* item2 = mKeyPairTable->item( idx.row(), 2 );

    if( item ) strPath = item->data(Qt::UserRole).toString();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    QString strName = item->text();
    QString strAlg = item1->text();
    QString strOpt = item2->text();

    if( strAlg == JS_PKI_KEY_NAME_ML_KEM )
    {
        berApplet->warningBox( tr( "%1 algorithm is not supported" ).arg( strAlg ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );


    JS_BIN_fileReadBER( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPri );
    MakeCSRDlg makeCSR;
    makeCSR.setInfo( tr( "Target [%1:%2:%3]").arg( strName ).arg( strAlg ).arg( strOpt ));
    makeCSR.setPriKey( &binPri );

    if( makeCSR.exec() == QDialog::Accepted )
    {
        QString strHexCSR = makeCSR.getCSRHex();
        JS_BIN_decodeHex( strHexCSR.toStdString().c_str(), &binCSR );

        ExportDlg exportDlg;
        exportDlg.setCSR( &binCSR );
        exportDlg.setName( strName );
        exportDlg.exec();
    }

end :
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binPri );
}

void KeyPairManDlg::clickLViewPriKey()
{
    int ret = 0;
    QDir dir;

    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    BIN binPri = {0,0};
    JS_BIN_fileReadBER( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPri );
    PriKeyInfoDlg priKeyInfo;
    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

    if( berApplet->settingsMgr()->supportKeyPairChange() == true )
    {
        BIN binRead = {0,0};
        priKeyInfo.readPrivateKey( &binRead );

        if( JS_BIN_cmp( &binRead, &binPri ) != 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
            if( bVal == true )
            {
                JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PRIVATE_KEY, strPriKeyPath.toLocal8Bit().toStdString().c_str() );
                berApplet->messageLog( tr( "Key change saved." ), this );
            }
        }

        JS_BIN_reset( &binRead );
    }

    JS_BIN_reset( &binPri );
}

void KeyPairManDlg::clickLViewPubKey()
{
    int ret = 0;
    QDir dir;

    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    BIN binPub = {0,0};
    JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );
    PriKeyInfoDlg priKeyInfo;
    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

    if( berApplet->settingsMgr()->supportKeyPairChange() == true )
    {
        BIN binRead = {0,0};
        priKeyInfo.readPublicKey( &binRead );

        if( JS_BIN_cmp( &binRead, &binPub ) != 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
            if( bVal == true )
            {
                JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PUBLIC_KEY, strPubKeyPath.toLocal8Bit().toStdString().c_str() );
                berApplet->messageLog( tr( "Key change saved." ), this );
            }
        }

        JS_BIN_reset( &binRead );
    }

    JS_BIN_reset( &binPub );
}

void KeyPairManDlg::clickLDecodePriKey()
{
    int ret = 0;
    QDir dir;

    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    BIN binPri = {0,0};

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    JS_BIN_fileReadBER( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPri );
    berApplet->decodeData( &binPri, strPriKeyPath );
    JS_BIN_reset( &binPri );
}

void KeyPairManDlg::clickLDecodePubKey()
{
    int ret = 0;
    QDir dir;

    BIN binPub = {0,0};

    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );
    berApplet->decodeData( &binPub, strPubKeyPath );
    JS_BIN_reset( &binPub );
}

void KeyPairManDlg::clickLRunSign()
{
    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    berApplet->mainWindow()->runSignVerify( true, false, strPriKeyPath, strPubKeyPath );
}

void KeyPairManDlg::clickLRunVerify()
{
    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    berApplet->mainWindow()->runSignVerify( false, false, strPriKeyPath, strPubKeyPath );
}

void KeyPairManDlg::clickLRunPubEnc()
{
    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    int nKeyType = -1;
    BIN binPub = {0,0};

    JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );
    nKeyType = JS_PKI_getPubKeyType( &binPub );
    JS_BIN_reset( &binPub );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr( "This key does not support public key encryption" ), this );
        return;
    }

    berApplet->mainWindow()->runPubEncDec( true, false, strPriKeyPath, strPubKeyPath );
}

void KeyPairManDlg::clickLRunPubDec()
{
    QString strPubKeyPath;
    QString strPriKeyPath;
    QString strPath = getSelectedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    strPubKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    int nKeyType = -1;
    BIN binPub = {0,0};

    JS_BIN_fileReadBER( strPubKeyPath.toLocal8Bit().toStdString().c_str(), &binPub );
    nKeyType = JS_PKI_getPubKeyType( &binPub );
    JS_BIN_reset( &binPub );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr( "This key does not support public key encryption" ), this );
        return;
    }

    berApplet->mainWindow()->runPubEncDec( false, false, strPriKeyPath, strPubKeyPath );
}

void KeyPairManDlg::clickSaveToList()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    QString strPriPath = mPriPathText->text();
    QString strPubPath = mPubPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    if( strPubPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Public Key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

    NameDlg nameDlg;

    if( nameDlg.exec() == QDialog::Accepted )
    {
        QDir dir;

        QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
        QString strName = nameDlg.mNameText->text();

        QString fullPath = QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName );
        if( dir.exists( fullPath ) )
        {
            berApplet->warningBox( tr( "The folder(%1) is already existed" ).arg( strName ), this );
            goto end;
        }
        else
        {
            dir.mkdir( fullPath );
        }

        QString strPriSavePath = QString( "%1/%2" ).arg( fullPath ).arg( kPrivateFile );
        QString strPubSavePath = QString( "%1/%2" ).arg( fullPath ).arg( kPublicFile );

        ret = writePriKeyPEM( &binPri, strPriSavePath );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "fail to write private key"), this );
            dir.rmdir( fullPath );
            goto end;
        }

        ret = writePubKeyPEM( &binPub, strPubSavePath );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "fail to write public key"), this );
            dir.rmdir( fullPath );
            goto end;
        }

        loadKeyPairList();

        berApplet->messageLog( tr( "Key pair saving was successful"), this );
    }


end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void KeyPairManDlg::clickMakeCSR()
{
    int ret = 0;
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
        ret = Save( now_t, TypeCSR, strCSRHex );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "fail to write: %1" ).arg(JERR(ret)), this );
            goto end;
        }
    }

end :
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

    ret = JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read public key: %1" ).arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read private key: %1" ).arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );
    if( ret == JSR_VALID )
        berApplet->messageBox( tr("The private key and the public key are correct"), this );
    else
        berApplet->warningBox( QString( tr("The private key and the public key are incorrect [%1]")).arg(ret), this );

end :
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

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        goto end;
    }

    nPBE = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
    nKeyType = JS_PKI_getPriKeyType( &binData );

    ret = JS_PKI_encryptPrivateKey( nPBE, strPasswd.toStdString().c_str(), &binData, &binInfo, &binEnc );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to encrypt private key: %1").arg(JERR(ret)), this);
        goto end;
    }

    ret = Save( now_t, TypePriInfo, &binInfo );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to write: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    ret = Save( now_t, TypeEncPri, &binEnc );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to write: %1" ).arg(JERR(ret)), this );
        goto end;
    }

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binInfo );
    JS_BIN_reset( &binEnc );
}


void KeyPairManDlg::clickViewCSR()
{
    int ret = -1;
    CSRInfoDlg csrInfo;

    BIN binData = {0,0};
    QString strFile = mCSRPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find CSR" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

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

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg(JERR(ret)), this);
        goto end;
    }

    ret = Save( now_t, TypePriKey, &binDec );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to write: %1" ).arg(JERR(ret)), this );
        goto end;
    }

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
    int ret = 0;
    BIN binPriKey = { 0,0 };
    PriKeyInfoDlg priKeyInfo;
    QString strPriPath = mPriPathText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a private key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPriKey );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    priKeyInfo.setPrivateKey( &binPriKey );
    priKeyInfo.exec();

    JS_BIN_reset( &binPriKey );
}

void KeyPairManDlg::viewPubKey()
{
    int ret = -1;
    BIN binPubKey = {0,0};
    PriKeyInfoDlg priKeyInfo;
    QString strPubPath = mPubPathText->text();

    if( strPubPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a public key"), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPubKey );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    priKeyInfo.setPublicKey( &binPubKey );
    priKeyInfo.exec();

    JS_BIN_reset( &binPubKey );
}

void KeyPairManDlg::findPriKey()
{
    QString strPath = mPriPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriPathText->setText( filePath );
}

void KeyPairManDlg::findPubKey()
{
    QString strPath = mPubPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPubPathText->setText( filePath );
}

void KeyPairManDlg::findEncPriKey()
{
    QString strPath = mEncPriPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
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
    int ret = -1;
    BIN binData = {0,0};
    QString strFile = mPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodePubKey()
{
    int ret = -1;
    BIN binData = {0,0};
    QString strFile = mPubPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Public Key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodeEncPriKey()
{
    int ret = -1;
    BIN binData = {0,0};
    QString strFile = mEncPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Encrypted Private Key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodePriInfo()
{
    int ret = -1;
    BIN binData = {0,0};
    QString strFile = mPriInfoPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no private key information" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::decodeCSR()
{
    int ret = -1;
    BIN binData = {0,0};
    QString strFile = mCSRPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find CSR" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::typePriKey()
{
    int ret = -1;
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mPriPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The private key type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::typePubKey()
{
    int ret = -1;
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mPubPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Public Key" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    nType = JS_PKI_getPubKeyType( &binData );
    berApplet->messageBox( tr( "The public key type is %1").arg( JS_PKI_getKeyAlgName( nType )), this);

    JS_BIN_reset( &binData );
}

void KeyPairManDlg::clickImport()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binP8 = {0,0};
    BIN binPFX = {0,0};
    BIN binCert = {0,0};

    QString strPath;
    QString strSelected;
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY_PKCS8_PFX, strPath, strSelected);

    if( fileName.length() < 1 ) return;

    QFileInfo fileInfo( fileName );
    QString strPasswd;
    QString strName;

    NameDlg nameDlg;
    PasswdDlg passDlg;


    QString strExt = fileInfo.suffix();

    if( strExt == "key" || strExt == "p8" || strExt == "pk8" )
    {

        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binP8 );

        ret = JS_PKI_decodePrivateKeyInfo( &binP8, &binPri );
        if( ret != 0 )
        {
            if( passDlg.exec() != QDialog::Accepted )
            {
                goto end;
            }

            strPasswd = passDlg.mPasswdText->text();

            ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binP8, NULL, &binPri );
            if( ret != 0 )
            {
                berApplet->warningBox( tr( "fail to decrypt private key: %1" ).arg(JERR(ret)), this );
                goto end;
            }
        }
    }
    else if( strExt == "pfx" || strExt == "p12" )
    {
        if( passDlg.exec() != QDialog::Accepted )
        {
            goto end;
        }

        strPasswd = passDlg.mPasswdText->text();

        ret = JS_PKI_decodePFX( &binPFX, strPasswd.toStdString().c_str(), &binPri, &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt PFX: %1" ).arg(JERR(ret)), this );
            goto end;
        }
    }
    else
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binPri );
    }

    ret = JS_PKI_getPubKeyFromPriKey( &binPri, &binPub );
    if( ret != 0 )
    {
        goto end;
    }

    if( nameDlg.exec() == QDialog::Accepted )
    {
        QDir dir;

        QString strKeyPairPath = berApplet->settingsMgr()->keyPairPath();
        QString strName = nameDlg.mNameText->text();

        QString fullPath = QString( "%1/%2" ).arg( strKeyPairPath ).arg( strName );
        if( dir.exists( fullPath ) )
        {
            berApplet->warningBox( tr( "The folder(%1) is already existed" ).arg( strName ), this );
            goto end;
        }
        else
        {
            dir.mkdir( fullPath );
        }

        QString strPriSavePath = QString( "%1/%2" ).arg( fullPath ).arg( kPrivateFile );
        QString strPubSavePath = QString( "%1/%2" ).arg( fullPath ).arg( kPublicFile );

        ret = writePubKeyPEM( &binPub, strPubSavePath );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to write public key: %1" ).arg(JERR(ret)), this );
            dir.rmpath( fullPath );
            goto end;
        }

        ret = writePriKeyPEM( &binPri, strPriSavePath );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to write private key: %1" ).arg(JERR(ret)), this );
            dir.remove( strPriSavePath );
            dir.rmpath( fullPath );
            goto end;
        }

        loadKeyPairList();

        berApplet->messageLog( tr( "Key pair saving was successful"), this );
    }


end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binP8 );
    JS_BIN_reset( &binPFX );
    JS_BIN_reset( &binCert );
}

void KeyPairManDlg::clickExport()
{
    int ret = -1;
    BIN binPri = {0,0};

    QString strPath;
    QString strPriPath;

    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem* item = mKeyPairTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    if( item ) strPath = item->data(Qt::UserRole).toString();
    strPriPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    ExportDlg exportDlg;
    exportDlg.setName( item->text() );
    exportDlg.setPrivateKey( &binPri );
    exportDlg.exec();
    JS_BIN_reset( &binPri );
}

const QString KeyPairManDlg::getPriPath()
{
    QString strPriPath;

    QString strPath = getSelectedPath();
    if( strPath.length() < 1 ) return strPriPath;

    strPriPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );
    return strPriPath;
}

const QString KeyPairManDlg::getPubPath()
{
    QString strPubPath;

    QString strPath = getSelectedPath();
    if( strPath.length() < 1 ) return strPubPath;

    strPubPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    return strPubPath;
}

const QString KeyPairManDlg::getName()
{
    QString strName;

    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem* item = mKeyPairTable->item( idx.row(), 0 );

    if( item ) strName = item->text();

    return strName;
}

int KeyPairManDlg::getPubKey( BIN *pPubKey )
{
    QString strPubPath;

    QString strPath = getSelectedPath();
    if( strPath.length() < 1 ) return -1;

    if( pPubKey == NULL ) return -2;

    strPubPath = QString( "%1/%2" ).arg( strPath ).arg( kPublicFile );
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), pPubKey );
    if( pPubKey->nLen <= 0 ) return -3;

    return 0;
}

int KeyPairManDlg::getPriKey( BIN *pPriKey )
{
    QString strPriPath;

    QString strPath = getSelectedPath();
    if( strPath.length() < 1 ) return -1;

    if( pPriKey == NULL ) return -2;

    strPriPath = QString( "%1/%2" ).arg( strPath ).arg( kPrivateFile );
    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pPriKey );
    if( pPriKey->nLen <= 0 ) return -3;

    return 0;
}

void KeyPairManDlg::clickOK()
{
    if( mode_ == KeyPairModeBase )
        return accept();

    if( getSelectedPath().length() < 1 )
    {
        berApplet->warningBox( tr( "Please select keypair" ), this );
        return;
    }

    return accept();
}
