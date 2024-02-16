#include <QDir>
#include <QFileInfo>
#include <QFileDialog>
#include <QMenu>

#include "common.h"
#include "trust_list_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "js_util.h"
#include "cert_info_dlg.h"

TrustListDlg::TrustListDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(clickDelete()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mTrustTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTableListMenuRequested(QPoint)));

    initialize();

    loadList();
}

TrustListDlg::~TrustListDlg()
{

}

void TrustListDlg::initialize()
{
    QStringList sTrustLabels = { tr( "Name" ), tr( "DN" ), tr( "From" ), tr( "To") };

    mTrustTable->horizontalHeader()->setStretchLastSection(true);
    mTrustTable->setColumnCount( sTrustLabels.size() );
    mTrustTable->setHorizontalHeaderLabels( sTrustLabels );
    mTrustTable->verticalHeader()->setVisible(false);
    mTrustTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mTrustTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mTrustTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mTrustTable->setColumnWidth( 1, 240 );
}

void TrustListDlg::clearList()
{
    int count = mTrustTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        mTrustTable->removeRow(0);
    }
}

void TrustListDlg::loadList()
{
    int ret = 0;
    int row = 0;

    clearList();

    QString strPath = berApplet->settingsMgr()->getTrustedCAPath();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();


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

        mTrustTable->insertRow( row );
        mTrustTable->setRowHeight( row, 10 );
        mTrustTable->setItem( row, 0, item );
        mTrustTable->setItem( row, 1, new QTableWidgetItem( sCertInfo.pSubjectName ));
        mTrustTable->setItem( row, 2, new QTableWidgetItem( sNotBefore ));
        mTrustTable->setItem( row, 3, new QTableWidgetItem( sNotAfter ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }
}

void TrustListDlg::clickAdd()
{
    int ret = 0;
    int bSelfSign = 0;
    long uHash = 0;

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
            int row = mTrustTable->rowCount();
            char    sNotBefore[64];
            char    sNotAfter[64];

            QTableWidgetItem *item = new QTableWidgetItem( strFileName );
            item->setData(Qt::UserRole, strFileName );

            JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
            JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

            mTrustTable->insertRow( row );
            mTrustTable->setRowHeight( row, 10 );
            mTrustTable->setItem( row, 0, item );
            mTrustTable->setItem( row, 1, new QTableWidgetItem( sCertInfo.pSubjectName ));
            mTrustTable->setItem( row, 2, new QTableWidgetItem( sNotBefore ));
            mTrustTable->setItem( row, 3, new QTableWidgetItem( sNotAfter ));
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

void TrustListDlg::clickDelete()
{
    QModelIndex idx = mTrustTable->currentIndex();

    QTableWidgetItem* item = mTrustTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
        berApplet->messageBox( tr( "Trust CA has been deleted"), this );
    else
    {
        berApplet->warningBox( tr( "failed to delete Trust CA" ), this );
        return;
    }

    loadList();
}

void TrustListDlg::viewCert()
{
    int ret = 0;
    BIN binCert = {0,0};

    QModelIndex idx = mTrustTable->currentIndex();

    QTableWidgetItem* item = mTrustTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( binCert.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no certificate"), this );
        return;
    }

    CertInfoDlg certInfo;
    certInfo.setCertBIN( &binCert );
    certInfo.exec();

    JS_BIN_reset( &binCert );
}

void TrustListDlg::slotTableListMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr( "Delete" ), this );
    QAction *viewAct = new QAction( tr( "View Cert" ), this );

    connect( delAct, SIGNAL(triggered()), this, SLOT(clickDelete()));
    connect( viewAct, SIGNAL(triggered()), this, SLOT(viewCert()));

    menu->addAction( delAct );
    menu->addAction( viewAct );

    menu->popup( mTrustTable->viewport()->mapToGlobal(pos));
}
