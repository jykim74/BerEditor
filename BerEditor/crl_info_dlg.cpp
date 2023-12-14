#include "mainwindow.h"
#include "ber_applet.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "common.h"

QTableWidgetItem* CRLInfoDlg::getExtNameItem( const QString strSN )
{
    QTableWidgetItem* item = NULL;

    if( strSN == JS_PKI_ExtNameAIA )
        item = new QTableWidgetItem( tr( "authorityInfoAccess" ));
    else if( strSN == JS_PKI_ExtNameAKI )
        item = new QTableWidgetItem( tr( "authorityKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameBC )
        item = new QTableWidgetItem( tr( "basicConstraints" ) );
    else if( strSN == JS_PKI_ExtNameCRLDP )
        item = new QTableWidgetItem( tr( "crlDistributionPoints" ) );
    else if( strSN == JS_PKI_ExtNameEKU )
        item = new QTableWidgetItem( tr( "extendedKeyUsage" ) );
    else if( strSN == JS_PKI_ExtNameIAN )
        item = new QTableWidgetItem( tr( "issuerAltName" ) );
    else if( strSN == JS_PKI_ExtNameKeyUsage )
        item = new QTableWidgetItem( tr( "keyUsage" ) );
    else if( strSN == JS_PKI_ExtNameNC )
        item = new QTableWidgetItem( tr( "nameConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePolicy )
        item = new QTableWidgetItem( tr( "certificatePolicies" ) );
    else if( strSN == JS_PKI_ExtNamePC )
        item = new QTableWidgetItem( tr( "policyConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePM )
        item = new QTableWidgetItem( tr( "policyMappings" ) );
    else if( strSN == JS_PKI_ExtNameSKI )
        item = new QTableWidgetItem( tr( "subjectKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameSAN )
        item = new QTableWidgetItem( tr( "subjectAltName" ) );
    else if( strSN == JS_PKI_ExtNameCRLNum )
        item = new QTableWidgetItem( tr( "crlNumber" ) );
    else if( strSN == JS_PKI_ExtNameIDP )
        item = new QTableWidgetItem( tr( "issuingDistributionPoint" ) );
    else if( strSN == JS_PKI_ExtNameCRLReason )
        item = new QTableWidgetItem( tr( "CRLReason" ) );
    else
        item = new QTableWidgetItem( strSN );


    return item;
}

CRLInfoDlg::CRLInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    ext_info_list_ = NULL;
    revoke_info_list_ = NULL;

    memset( &crl_bin_, 0x00, sizeof(crl_bin_));
    memset( &crl_info_, 0x00, sizeof(crl_info_));
    tabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

CRLInfoDlg::~CRLInfoDlg()
{
    JS_BIN_reset( &crl_bin_ );
    JS_PKI_resetCRLInfo( &crl_info_ );
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );
}

void CRLInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

int CRLInfoDlg::setCRLPath(const QString strPath )
{
    int ret = 0;
    JS_BIN_reset( &crl_bin_ );

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &crl_bin_ );

    return ret;
}

void CRLInfoDlg::setCRL_BIN( const BIN *pCRL )
{
    JS_BIN_reset( &crl_bin_ );
    JS_BIN_copy( &crl_bin_, pCRL );
}

void CRLInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binFinger = {0,0};

    char    sThisUpdate[64];
    char    sNextUpdate[64];

    tabWidget->setCurrentIndex(0);

    JS_PKI_resetCRLInfo( &crl_info_ );

    if( crl_bin_.nLen < 1 )
    {
        berApplet->warningBox( tr("Select CRL"), this );
        return;
    }

    clearTable();
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );

    ret = JS_PKI_getCRLInfo( &crl_bin_, &crl_info_, &ext_info_list_, &revoke_info_list_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("fail to get CRL information"), this );
        close();
        return;
    }

    JS_PKI_genHash( "SHA1", &crl_bin_, &binFinger );

    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(crl_info_.nVersion+1)));
    i++;

    if( crl_info_.pIssuerName )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("IssuerName")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pIssuerName)));
        i++;
    }


    JS_UTIL_getDateTime( crl_info_.uThisUpdate, sThisUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("ThisUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sThisUpdate)));
    i++;

    JS_UTIL_getDateTime( crl_info_.uNextUpdate, sNextUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("NextUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdate)));
    i++;

    if( crl_info_.pSignAlgorithm )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("SignAlgorithm")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignAlgorithm)));
        i++;
    }

    if( crl_info_.pSignature )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("Signature")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignature)));
        i++;
    }

    if( ext_info_list_ )
    {
        JExtensionInfoList *pCurList = ext_info_list_;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mCRLListTable->insertRow(i);
            mCRLListTable->setRowHeight(i,10);
            mCRLListTable->setItem(i,0, getExtNameItem(strSN));
            mCRLListTable->setItem(i,1, item );

            pCurList = pCurList->pNext;
            i++;
        }
    }

    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFinger.pVal, binFinger.nLen))));
    i++;

    if( revoke_info_list_ )
    {
        int k = 0;
        JRevokeInfoList *pCurRevList = revoke_info_list_;

        while( pCurRevList )
        {
            mRevokeListTable->insertRow(k);
            mRevokeListTable->setRowHeight(k,10);
            mRevokeListTable->setItem( k, 0, new QTableWidgetItem(QString("%1").arg( pCurRevList->sRevokeInfo.pSerial)));
            mRevokeListTable->setItem( k, 1, new QTableWidgetItem(QString("%1").arg( pCurRevList->sRevokeInfo.uRevokeDate)));

            pCurRevList = pCurRevList->pNext;
            k++;
        }
    }

    JS_BIN_reset( &binFinger );
}

void CRLInfoDlg::initUI()
{
    QStringList sCRLLabels = { tr("Field"), tr("Value") };

    mCRLListTable->clear();
    mCRLListTable->horizontalHeader()->setStretchLastSection(true);
    mCRLListTable->setColumnCount(2);
    mCRLListTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLListTable->verticalHeader()->setVisible(false);
    mCRLListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sRevokeLabels = { tr("Serial"), tr("RevokedDate") };
    mRevokeListTable->clear();
    mRevokeListTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeListTable->setColumnCount(2);
    mRevokeListTable->setHorizontalHeaderLabels( sRevokeLabels );
    mRevokeListTable->verticalHeader()->setVisible(false);
    mRevokeListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mRevokeDetailTable->clear();
    mRevokeDetailTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeDetailTable->setColumnCount(2);
    mRevokeDetailTable->setHorizontalHeaderLabels(sCRLLabels);
    mRevokeDetailTable->verticalHeader()->setVisible(false);
    mRevokeDetailTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeDetailTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mCRLListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCRLField(QModelIndex)));
    connect( mRevokeListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickRevokeField(QModelIndex)));
}

void CRLInfoDlg::clearTable()
{
    int rowCnt = mCRLListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mCRLListTable->removeRow(0);

    rowCnt = mRevokeListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeListTable->removeRow(0);

    rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);
}

void CRLInfoDlg::clickCRLField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mCRLListTable->item( row, 1 );
    if( item == NULL ) return;

    mCRLDetailText->setPlainText( item->text() );
}

void CRLInfoDlg::clickRevokeField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    int rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);

    JRevokeInfoList *pRevInfoList = revoke_info_list_;

    for( int i = 0; i < row; i++ )
    {
        pRevInfoList = pRevInfoList->pNext;
    }

    char sRevokeDate[64];

    JS_UTIL_getDateTime( pRevInfoList->sRevokeInfo.uRevokeDate, sRevokeDate );

    mRevokeDetailTable->insertRow(0);
    mRevokeDetailTable->setRowHeight(0,10);
    mRevokeDetailTable->setItem( 0, 0, new QTableWidgetItem( QString("Serial" )));
    mRevokeDetailTable->setItem( 0, 1, new QTableWidgetItem( QString( pRevInfoList->sRevokeInfo.pSerial )));

    mRevokeDetailTable->insertRow(1);
    mRevokeDetailTable->setRowHeight(1,10);
    mRevokeDetailTable->setItem( 1, 0, new QTableWidgetItem( QString("RevokedDate" )));
    mRevokeDetailTable->setItem( 1, 1, new QTableWidgetItem( QString( "%1" ).arg( sRevokeDate )));

    if( pRevInfoList->sRevokeInfo.sExtReason.pOID )
    {
        QString strValue = pRevInfoList->sRevokeInfo.sExtReason.pValue;
        QString strSN = pRevInfoList->sRevokeInfo.sExtReason.pOID;
        bool bCrit = pRevInfoList->sRevokeInfo.sExtReason.bCritical;

        mRevokeDetailTable->insertRow(2);
        mRevokeDetailTable->setRowHeight(2,10);

        getInfoValue( &pRevInfoList->sRevokeInfo.sExtReason, strValue );

        QTableWidgetItem *item = new QTableWidgetItem( strValue );
        if( bCrit )
            item->setIcon(QIcon(":/images/critical.png"));
        else
            item->setIcon(QIcon(":/images/normal.png"));

        mRevokeDetailTable->setItem(2,0, new QTableWidgetItem(QString("%1").arg(strSN)));
        mRevokeDetailTable->setItem(2,1,item);
    }

}
