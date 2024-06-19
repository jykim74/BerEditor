#include <QDir>
#include <QFileInfo>

#include "cert_man_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_error.h"
#include "js_util.h"

CertManDlg::CertManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

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

    QString strPath = berApplet->settingsMgr()->getCertPath();
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
