/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "mainwindow.h"
#include "ber_applet.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "common.h"
#include "cert_man_dlg.h"
#include "settings_mgr.h"


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

    crl_path_.clear();
    memset( &crl_bin_, 0x00, sizeof(crl_bin_));
    memset( &crl_info_, 0x00, sizeof(crl_info_));

    connect( mSaveBtn, SIGNAL(clicked()), this, SLOT(clickSave()));
    connect( mSaveToManBtn, SIGNAL(clicked()), this, SLOT(clickSaveToMan()));
    connect( mDecodeCRLBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCRL()));
    connect( mVerifyCRLBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCRL()));

    tabWidget->setCurrentIndex(0);
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCRLTab->layout()->setSpacing(5);
    mCRLTab->layout()->setMargin(5);
    mRevokeTab->layout()->setSpacing(5);
    mRevokeTab->layout()->setMargin(5);

    mManGroup->layout()->setSpacing(5);
    mManGroup->layout()->setMargin(5);
#endif


    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CRLInfoDlg::~CRLInfoDlg()
{
    resetData();
}

void CRLInfoDlg::resetData()
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

void CRLInfoDlg::clickSave()
{
    saveAsPEM( &crl_bin_ );
}

void CRLInfoDlg::clickSaveToMan()
{
    int ret = 0;
    QString strCRLPath = berApplet->settingsMgr()->CRLPath();

    ret = CertManDlg::writeCRL( strCRLPath, &crl_bin_ );
    if( ret > 0 )
        berApplet->messageLog( tr( "The CRL is saved to manager folder" ), this );
    else
        berApplet->warnLog( tr( "failed to save to manager folder: %1" ).arg( ret ), this );
}

void CRLInfoDlg::clickDecodeCRL()
{
    berApplet->decodeData( &crl_bin_, crl_path_ );
}

void CRLInfoDlg::clickVerifyCRL()
{
    int ret = 0;
    BIN binCA = {0,0};
    QString strPath;

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFileName.length() > 0 )
    {
        JCertInfo sCertInfo;
        QString strCertName;
        QString strCRLName;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binCA );

        ret = JS_PKI_getCertInfo( &binCA, &sCertInfo, NULL );
        if( ret != 0)
        {
            berApplet->warningBox( tr( "invalid certificate"), this );
            JS_BIN_reset( &binCA );
            return;
        }

        strCertName = sCertInfo.pSubjectName;
        strCRLName = crl_info_.pIssuerName;

        if( strCertName != strCRLName )
        {
            berApplet->warningBox( tr( "The certificate is not issuer of the CRL" ), this );
            berApplet->elog( QString( "CertName: %1" ).arg( strCertName ) );
            berApplet->elog( QString( "CRLName: %1").arg( strCRLName) );

            JS_BIN_reset( &binCA );
            JS_PKI_resetCertInfo( &sCertInfo );
            return;
        }

        ret = JS_PKI_verifyCRL( &crl_bin_, &binCA );
        if( ret == 1 )
            berApplet->messageBox( tr( "CRL verification successful" ), this );
        else
            berApplet->warningBox( tr( "CRL verification failed [%1]").arg( ret ), this );

        JS_BIN_reset( &binCA );
        JS_PKI_resetCertInfo( &sCertInfo );
    }
}

int CRLInfoDlg::setCRLPath(const QString strPath )
{
    int ret = 0;
    resetData();

    crl_path_ = strPath;
    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &crl_bin_ );

    return ret;
}

void CRLInfoDlg::setCRL_BIN( const BIN *pCRL )
{
    resetData();
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

    if( berApplet->isLicense() == false ) mManGroup->setEnabled( false );

    JS_PKI_resetCRLInfo( &crl_info_ );

    if( crl_bin_.nLen < 1 )
    {
        berApplet->warningBox( tr("Select a CRL"), this );
        return;
    }

    clearTable();
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );

    ret = JS_PKI_getCRLInfo( &crl_bin_, &crl_info_, &ext_info_list_, &revoke_info_list_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to get CRL information"), this );
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
    if( berApplet->isLicense() == true )
        mSaveToManBtn->show();
    else
        mSaveToManBtn->hide();
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

int CRLInfoDlg::saveAsPEM( const BIN *pData )
{
    if( pData == NULL || pData->nLen <= 0 ) return -1;


    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath;

    QString strFilter = tr("CRL Files (*.crl);;PEM Files (*.pem);;All Files (*.*)");
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( this,
                                                    tr("Export Files"),
                                                    strPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 )
    {
        int ret = JS_BIN_writePEM( pData, JS_PEM_TYPE_CRL, fileName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "The CRL was saved in PEM format." ), this );
        }
    }

    return 0;
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
