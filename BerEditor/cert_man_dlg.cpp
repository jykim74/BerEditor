#include <QDir>
#include <QFileInfo>

#include "cert_man_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "passwd_dlg.h"
#include "new_passwd_dlg.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_error.h"
#include "js_util.h"

CertManDlg::CertManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

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

}

void CertManDlg::showEvent(QShowEvent *event)
{
    initialize();
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

    mCA_CertTable->clear();
    mCA_CertTable->horizontalHeader()->setStretchLastSection(true);
    mCA_CertTable->setColumnCount( sTableLabels.size() );
    mCA_CertTable->setHorizontalHeaderLabels( sTableLabels );
    mCA_CertTable->verticalHeader()->setVisible(false);
    mCA_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCA_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCA_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    setGroupHide(true);
}

void CertManDlg::initialize()
{
    mTabWidget->setCurrentIndex(0);

    loadEEList();
    loadTrustCAList();

    mCertPathText->setText( berApplet->settingsMgr()->certPath() );
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

    clearEEList();

    QString strPath = berApplet->settingsMgr()->certPath();
    QDir dir( strPath );

    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        if( file.isFile() ) continue;

        loadList( file.absoluteFilePath() );
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
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mCA_CertTable->setItem( row, 0, item );
        mCA_CertTable->setItem( row, 1, new QTableWidgetItem( getKeyTypeName( nKeyType )));
        mCA_CertTable->setItem( row, 2, new QTableWidgetItem( sNotBefore ));
        mCA_CertTable->setItem( row, 3, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }
}

int CertManDlg::saveStorage( const BIN *pEncPriKey, const BIN *pCert )
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
        berApplet->warningBox( tr( "fail to decode certificate: %1" ).arg( ret ), this );
        goto end;
    }

    strPath += "/";
    strPath += sCertInfo.pSubjectName;
    dir.mkdir( strPath );

    strPriPath = QString("%1/%2").arg( strPath ).arg( "private.key" );
    strCertPath = QString("%1/%2").arg( strPath ).arg( "certificate.crt" );

    JS_BIN_writePEM( pCert, JS_PEM_TYPE_CERTIFICATE, strCertPath.toLocal8Bit().toStdString().c_str() );
    JS_BIN_writePEM( pEncPriKey, JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY, strCertPath.toLocal8Bit().toStdString().c_str() );

    loadEEList();

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    return 0;
}

int CertManDlg::readStorage( BIN *pEncPriKey, BIN *pCert )
{
    QTableWidgetItem* item = mEE_CertTable->currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item" ), this );
        return -1;
    }

    QString strPriPath;
    QString strCertPath;

    QString strPath = item->data(Qt::UserRole).toString();

    strPriPath = QString("%1/%2").arg( strPath ).arg( "private.key" );
    strCertPath = QString("%1/%2").arg( strPath ).arg( "certificate.crt" );

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pEncPriKey );
    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), pCert );

    return 0;
}

void CertManDlg::clickViewCert()
{

}

void CertManDlg::clickDeleteCert()
{

}

void CertManDlg::clickDecodeCert()
{

}

void CertManDlg::clickDecodePriKey()
{

}

void CertManDlg::clickCheckKeyPair()
{

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

    if( passwdDlg.exec() != QDialog::Accepted )
        return;

    strPass = passwdDlg.mPasswdText->text();

    strPFXFile = findFile( this, JS_FILE_TYPE_PFX, strPFXFile );
    if( strPFXFile.length() < 1 ) return;

    JS_BIN_fileReadBER( strPFXFile.toLocal8Bit().toStdString().c_str(), &binPFX );

    ret = JS_PKI_decodePFX( &binPFX, strPass.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg( ret ));
        goto end;
    }

    ret = saveStorage( &binPri, &binCert );
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

    ret = readStorage( &binEncPri, &binCert );
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

}

void CertManDlg::clickDecodeTrust()
{

}
