#include <QDir>
#include <QFileInfo>

#include "cert_man_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "passwd_dlg.h"
#include "new_passwd_dlg.h"
#include "cert_info_dlg.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_error.h"
#include "js_util.h"
#include "js_pki_tools.h"

static const QString kCertFile = "js_cert.crt";
static const QString kPriKeyFile = "js_private.key";

CertManDlg::CertManDlg(QWidget *parent) :
    QDialog(parent)
{
    mode_ = ManModeBase;
    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &cert_, 0x00, sizeof(BIN));

    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    connect( mViewCertBtn, SIGNAL(clicked()), this, SLOT(clickViewCert()));
    connect( mDelCertBtn, SIGNAL(clicked()), this, SLOT(clickDeleteCert()));
    connect( mDecodeCertBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCert()));
    connect( mDecodePriKeyBtn, SIGNAL(clicked()), this, SLOT(clickDecodePriKey()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mImportBtn, SIGNAL(clicked()), this, SLOT(clickImport()));
    connect( mExportBtn, SIGNAL(clicked()), this, SLOT(clickExport()));
    connect( mChangePasswdBtn, SIGNAL(clicked()), this, SLOT(clickChangePasswd()));
    connect( mAddTrustBtn, SIGNAL(clicked()), this, SLOT(clickAddTrust()));
    connect( mRemoveTrustBtn, SIGNAL(clicked()), this, SLOT(clickRemoveTrust()));
    connect( mViewTrustBtn, SIGNAL(clicked()), this, SLOT(clickViewTrust()));
    connect( mDecodeTrustBtn, SIGNAL(clicked()), this, SLOT(clickDecodeTrust()));

    initUI();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

CertManDlg::~CertManDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &cert_ );
}

void CertManDlg::setMode( int nMode )
{
    mode_ = nMode;
}

void CertManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void CertManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CertManDlg::closeEvent(QCloseEvent *event )
{
    setGroupHide( false );
    setOKHide( false );
}

void CertManDlg::initUI()
{
    QStringList sTableLabels = { tr( "Subject DN" ), tr( "Algorithm"), tr( "Expire" ), tr( "Issuer DN" ) };

    mEE_CertTable->clear();
    mEE_CertTable->horizontalHeader()->setStretchLastSection(true);
    mEE_CertTable->setColumnCount( sTableLabels.size() );
    mEE_CertTable->setHorizontalHeaderLabels( sTableLabels );
    mEE_CertTable->verticalHeader()->setVisible(false);
    mEE_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mEE_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mEE_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sCATableLabels = { tr( "Name" ), tr( "Subject DN" ), tr( "Algorithm"), tr( "Expire" ), tr( "Issuer DN" ) };

    mCA_CertTable->clear();
    mCA_CertTable->horizontalHeader()->setStretchLastSection(true);
    mCA_CertTable->setColumnCount( sCATableLabels.size() );
    mCA_CertTable->setHorizontalHeaderLabels( sCATableLabels );
    mCA_CertTable->verticalHeader()->setVisible(false);
    mCA_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCA_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCA_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void CertManDlg::initialize()
{
    loadTrustCAList();

    mTabWidget->setCurrentIndex(0);
    mCertPathText->setText( berApplet->settingsMgr()->certPath() );

    if( mode_ == ManModeSelCert )
        mEE_PasswdText->setEnabled(false);
    else
        mEE_PasswdText->setEnabled(true);

    if( mode_ == ManModeTrust )
    {
        setTrustOnly();
        setGroupHide( false );
    }
    else if( mode_ == ManModeSelBoth || mode_ == ManModeSelCert )
    {
        loadEEList();
        setGroupHide(true);
    }
    else
    {
        loadEEList();
        setGroupHide( false );
    }
}

void CertManDlg::setGroupHide( bool bHide )
{
    if( bHide == true )
    {
        mEE_ManGroup->hide();
        mCA_ManGroup->hide();
    }
    else
    {
        mEE_ManGroup->show();
        mCA_ManGroup->show();
    }
}

void CertManDlg::setOKHide( bool bHide )
{
    if( bHide == true )
        mOKBtn->hide();
    else
        mOKBtn->show();
}

void CertManDlg::setTrustOnly()
{
    setOKHide(true);
    setGroupHide( false );
    mCancelBtn->setText(tr("Close"));
    mTabWidget->setTabEnabled(0,false);
    mTabWidget->setCurrentIndex(1);
}

const QString CertManDlg::getPriKeyHex()
{
    return getHexString( &pri_key_ );
}

const QString CertManDlg::getCertHex()
{
    return getHexString( &cert_ );
}

int CertManDlg::getPriKey( BIN *pPriKey )
{
    if( pri_key_.nLen < 1 ) return -1;

    JS_BIN_copy( pPriKey, &pri_key_ );
}

int CertManDlg::getCert( BIN *pCert )
{
    if( cert_.nLen < 1 ) return -1;

    JS_BIN_copy( pCert, &cert_ );
}

void CertManDlg::clearCAList()
{
    int count = mCA_CertTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        mCA_CertTable->removeRow(0);
    }
}

void CertManDlg::clearEEList()
{
    int count = mEE_CertTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        mEE_CertTable->removeRow(0);
    }
}

void CertManDlg::loadList( const QString strDir )
{
    int ret = 0;
    int row = 0;

    QDir dir( strDir );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];

        if( file.isFile() == false ) continue;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();

        if( strSuffix != "crt" && strSuffix != "key" ) continue;

        QTableWidgetItem *item = new QTableWidgetItem( strName );
        item->setData(Qt::UserRole, file.filePath() );
        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

        mCA_CertTable->insertRow( row );
        mCA_CertTable->setRowHeight( row, 10 );
        mCA_CertTable->setItem( row, 0, new QTableWidgetItem( sCertInfo.pSubjectName ));
        mCA_CertTable->setItem( row, 1, new QTableWidgetItem( sNotBefore ));
        mCA_CertTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }
}

void CertManDlg::loadEEList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearEEList();

    QString strPath = berApplet->settingsMgr()->certPath();
    QDir dir( strPath );

    for (const QFileInfo &folder : dir.entryInfoList(QDir::Dirs))
    {
        if( folder.isFile() ) continue;

        QString strCertPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kCertFile );
        QFileInfo certFile( strCertPath );
        QString strPriKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPriKeyFile );
        QFileInfo priKeyFile( strPriKeyPath );

        if( certFile.exists() == false || priKeyFile.exists() == false ) continue;

        //loadList( folder.absoluteFilePath() );

        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = certFile.baseName();
        QString strSuffix = certFile.suffix();

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

        mEE_CertTable->insertRow( row );
        mEE_CertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, folder.filePath() );

        mEE_CertTable->setItem( row, 0, item );
        mEE_CertTable->setItem( row, 1, new QTableWidgetItem( getKeyTypeName( nKeyType )));
        mEE_CertTable->setItem( row, 2, new QTableWidgetItem( sNotBefore ));
        mEE_CertTable->setItem( row, 3, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }
}

void CertManDlg::loadTrustCAList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearCAList();

    QString strPath = berApplet->settingsMgr()->getTrustedCAPath();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();


        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

        mCA_CertTable->insertRow( row );
        mCA_CertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( strName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mCA_CertTable->setItem( row, 0, item );
        mCA_CertTable->setItem( row, 1, new QTableWidgetItem( sCertInfo.pSubjectName ));
        mCA_CertTable->setItem( row, 2, new QTableWidgetItem( getKeyTypeName( nKeyType )));
        mCA_CertTable->setItem( row, 3, new QTableWidgetItem( sNotBefore ));
        mCA_CertTable->setItem( row, 4, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }
}

int CertManDlg::writePriKeyCert( const BIN *pEncPriKey, const BIN *pCert )
{
    int ret = 0;
    JCertInfo sCertInfo;
    QString strPath = berApplet->settingsMgr()->certPath();

    QString strPriPath;
    QString strCertPath;
    QDir dir;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to decode certificate: %1" ).arg( ret ) );
        goto end;
    }

    strPath += "/";
    strPath += sCertInfo.pSubjectName;

    if( dir.mkpath( strPath ) == false )
    {
        berApplet->elog( QString( "fail to make path: %1").arg( strPath ) );
        goto end;
    }

    strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    JS_BIN_writePEM( pCert, JS_PEM_TYPE_CERTIFICATE, strCertPath.toLocal8Bit().toStdString().c_str() );
    JS_BIN_writePEM( pEncPriKey, JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY, strPriPath.toLocal8Bit().toStdString().c_str() );

    loadEEList();

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    return 0;
}

int CertManDlg::changePriKey( const BIN *pNewEncPriKey )
{
    QDir dir;
    QString strPath = getSeletedPath();

    if( strPath.length() < 1 )
        return -1;

    strPath += "/";
    strPath += kPriKeyFile;

    dir.remove( strPath );
    JS_BIN_fileWrite( pNewEncPriKey, strPath.toLocal8Bit().toStdString().c_str() );

    return 0;
}

const QString CertManDlg::getSeletedPath()
{
    QString strPath;

    QTableWidgetItem* item = mEE_CertTable->currentItem();
    if( item ) strPath = item->data(Qt::UserRole).toString();

    return strPath;
}

int CertManDlg::readPriKeyCert( BIN *pEncPriKey, BIN *pCert )
{
    QString strPriPath;
    QString strCertPath;

    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return -1;
    }

    strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pEncPriKey );
    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), pCert );

    return 0;
}

int CertManDlg::readCert( BIN *pCert )
{
    QString strCertPath;

    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return -1;
    }

    strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), pCert );

    return 0;
}

void CertManDlg::clickViewCert()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    CertInfoDlg certInfo;

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to read certificate: %1" ).arg(ret ), this);
        goto end;
    }

    certInfo.setCertBIN( &binCert );
    certInfo.exec();

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickDeleteCert()
{
    int ret = 0;

    bool bVal = false;
    QDir dir;
    QString strCertPath;
    QString strPriKeyPath;

    bVal = berApplet->yesOrCancelBox( tr( "Are you sure to delete the certificate" ), this, false );
    if( bVal == false ) return;

    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "The certificate is not selected" ), this );
        return;
    }

    strCertPath = QString( "%1/%2" ).arg( strPath ).arg( kCertFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPriKeyFile );

    dir.remove( strCertPath );
    dir.remove( strPriKeyPath );
    dir.remove( strPath );
}

void CertManDlg::clickDecodeCert()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    QString strPath = getSeletedPath();

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to read certificate: %1" ).arg(ret ), this);
        goto end;
    }

    strPath += "/";
    strPath += kCertFile;

    berApplet->decodeData( &binCert, strPath );

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickDecodePriKey()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    QString strPath = getSeletedPath();

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to read private key: %1" ).arg(ret ), this);
        goto end;
    }

    strPath += "/";
    strPath += kPriKeyFile;
    berApplet->decodeData( &binEncPri, strPath );

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickCheckKeyPair()
{
    int ret = 0;

    BIN binPriKey = {0,0};
    BIN binEncPriKey = {0,0};
    BIN binCert = {0,0};

    QString strPass = mEE_PasswdText->text();

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        return;
    }

    ret = readPriKeyCert( &binEncPriKey, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to read private key and certificate: %1").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( ret ), this );
        goto end;
    }

    ret = JS_PKI_IsValidPriKeyCert( &binPriKey, &binCert );
    if( ret == 1 )
    {
        berApplet->messageLog( tr( "The private key and ceritificate are good"), this );
    }
    else
    {
        berApplet->warnLog( tr( "The private key and certificate are bad" ), this );
    }

end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binCert );
}


void CertManDlg::clickImport()
{
    int ret = 0;
    QString strPass;
    PasswdDlg passwdDlg;
    QString strPFXFile = berApplet->curFolder();

    BIN binPFX = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};

    strPFXFile = findFile( this, JS_FILE_TYPE_PFX, strPFXFile );
    if( strPFXFile.length() < 1 ) return;

    JS_BIN_fileReadBER( strPFXFile.toLocal8Bit().toStdString().c_str(), &binPFX );

    if( passwdDlg.exec() != QDialog::Accepted )
        return;

    strPass = passwdDlg.mPasswdText->text();

    ret = JS_PKI_decodePFX( &binPFX, strPass.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg( ret ), this);
        goto end;
    }

    ret = writePriKeyCert( &binPri, &binCert );
    if( ret == 0 )
    {
        berApplet->messageLog( tr( "The private key and certificate are saved successfully"), this );
    }

end :
    JS_BIN_reset( &binPFX );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickExport()
{
    int ret = 0;
    int nKeyType = 0;

    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    BIN binPFX = {0,0};

    QString strPass = mEE_PasswdText->text();

    QString strPFXPath;

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password"), this );
        return;
    }

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 ) goto end;

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPri, NULL, &binPri );
    if( ret != 0 ) goto end;

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    ret = JS_PKI_encodePFX( &binPFX, nKeyType, strPass.toStdString().c_str(), -1, &binPri, &binCert );
    if( ret != 0 ) goto end;

    strPFXPath = findSaveFile( this, JS_FILE_TYPE_PFX, berApplet->curFolder() );
    JS_BIN_fileWrite( &binPFX, strPFXPath.toStdString().c_str() );

    berApplet->messageLog( tr( "PFX saved successfully:%1").arg( strPFXPath ), this );

end :
    if( ret != 0 )
        berApplet->warnLog( tr( "fail to export PFX: %1" ).arg( ret ), this );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPFX );
}

void CertManDlg::clickChangePasswd()
{
    int ret = 0;
    int nKeyType = -1;

    BIN binPriKey = {0,0};
    BIN binEncPriKey = {0,0};
    BIN binNewEncPriKey = {0,0};
    BIN binCert = {0,0};

    NewPasswdDlg newPasswd;
    QString strPass = mEE_PasswdText->text();

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        return;
    }

    ret = readPriKeyCert( &binEncPriKey, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to read private key and certificate: %1").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( ret ), this );
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binPriKey );

    if( newPasswd.exec() == QDialog::Accepted )
    {
        QString strNewPass = newPasswd.mPasswdText->text();

        ret = JS_PKI_encryptPrivateKey( nKeyType, -1, strNewPass.toStdString().c_str(), &binPriKey, NULL, &binNewEncPriKey );
        if( ret != 0 )
        {
            berApplet->warnLog( tr( "fail to encrypt private key: %1").arg( ret ), this );
            goto end;
        }

        ret = changePriKey( &binNewEncPriKey );
        if( ret != 0 )
        {
            berApplet->warnLog( tr( "fail to change private key: %1").arg(ret ), this );
            goto end;
        }

        berApplet->messageLog( tr( "The private key password is changed successfully" ), this );
    }


end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binNewEncPriKey );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickOK()
{
    int ret = 0;

    if( mode_ != ManModeSelCert && mode_ == ManModeSelBoth )
    {
        QDialog::accept();
        return;
    }

    BIN binEncPriKey = {0,0};
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};

    if( mode_ == ManModeSelCert )
    {
        ret = readCert( &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to read the certificate" ), this );
            goto end;
        }

        JS_BIN_copy( &cert_, &binCert );
    }
    else
    {
        QString strPass = mEE_PasswdText->text();

        JS_BIN_reset( &pri_key_ );
        JS_BIN_reset( &cert_ );

        if( strPass.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            return;
        }

        ret = readPriKeyCert( &binEncPriKey, &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to read the private key and certificate" ), this );
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt the private key: %1" ).arg( ret ), this );
            goto end;
        }

        JS_BIN_copy( &pri_key_, &binPriKey );
        JS_BIN_copy( &cert_, &binCert );
    }

end :
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );

    if( ret == 0 )
        QDialog::accept();
    else
        QDialog::reject();
}

void CertManDlg::clickAddTrust()
{
    int ret = 0;
    int bSelfSign = 0;
    unsigned long uHash = 0;

    BIN binCA = {0,0};
    JCertInfo sCertInfo;
    QString strPath = berApplet->curFile();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    QString strTrustPath = berApplet->settingsMgr()->trustedCAPath();

    QDir dir;

    if( dir.exists( strPath ) == false )
    {
        if( dir.mkpath( strPath ) == false )
        {
            berApplet->warningBox( tr( "fail to make TrustCA folder: %1").arg( strPath ), this );
            return;
        }
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( fileName.length() > 0 )
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCA );
        ret = JS_PKI_getCertInfo2( &binCA, &sCertInfo,NULL, &bSelfSign );
        if( ret != 0 ) goto end;

        if( bSelfSign == 0 )
        {
            berApplet->warningBox( tr( "This certificate is not self-signed"), this );
            goto end;
        }

        ret = JS_PKI_getSubjectNameHash( &binCA, &uHash );
        if( ret != 0 ) goto end;

        QString strFileName = QString( "%1.0" ).arg( uHash, 8, 16, QLatin1Char('0'));
        QString strSaveName = QString( "%1/%2" ).arg( strTrustPath ).arg( strFileName );
        if( QFileInfo::exists( strFileName ) == true )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed").arg( strSaveName ), this );
            goto end;
        }

        ret = JS_BIN_writePEM( &binCA, JS_PEM_TYPE_CERTIFICATE, strSaveName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            loadTrustCAList();
            berApplet->messageBox( tr( "The Certificate saved to trustedCA folder"), this );
        }
        else
        {
            berApplet->warningBox( tr( "The Certificate failed to save to trustedCA folder:%1" ).arg(ret), this );
        }
    }

end :
    JS_BIN_reset( &binCA );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void CertManDlg::clickRemoveTrust()
{
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    bool bVal = berApplet->yesOrCancelBox( tr( "Do you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
    {
        loadTrustCAList();
        berApplet->messageBox( tr( "Trust CA has been deleted"), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete Trust CA" ), this );
        return;
    }

}

void CertManDlg::clickViewTrust()
{
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();

    CertInfoDlg certInfo;
    certInfo.setCertPath( strPath );
    certInfo.exec();
}

void CertManDlg::clickDecodeTrust()
{
    BIN binCert = {0,0};
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    berApplet->decodeData( &binCert, strPath );
    JS_BIN_reset( &binCert );
}
