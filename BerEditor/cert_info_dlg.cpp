#include "mainwindow.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_util.h"
#include "common.h"


CertInfoDlg::CertInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    cert_path_ = "";
    tabWidget->setCurrentIndex(0);
}

CertInfoDlg::~CertInfoDlg()
{

}

void CertInfoDlg::setCertPath(const QString strPath)
{
    cert_path_ = strPath;
}

void CertInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CertInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binCert = {0,0};
    JCertInfo  sCertInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    char    sNotBefore[64];
    char    sNotAfter[64];

    if( cert_path_.length() < 1 )
    {
        berApplet->warningBox( tr( "Select certificate"), this );
        this->hide();
        return;
    }

    clearTable();

    JS_BIN_fileRead( cert_path_.toLocal8Bit().toStdString().c_str(), &binCert );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("fail to get certificate information"), this );
        JS_BIN_reset( &binCert );
        this->hide();
        return;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(sCertInfo.nVersion + 1)));
    i++;

    if( sCertInfo.pSerial )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSerial)));
        i++;
    }

    JS_UTIL_getDateTime( sCertInfo.uNotBefore, sNotBefore );
    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotBefore")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBefore)));
    i++;

    JS_UTIL_getDateTime( sCertInfo.uNotAfter, sNotAfter );
    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfter)));
    i++;

    if( sCertInfo.pSubjectName )
    {
        QString name = QString::fromUtf8( sCertInfo.pSubjectName );

        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    if( sCertInfo.pPublicKey )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pPublicKey)));
        i++;
    }

    if( sCertInfo.pIssuerName )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("IssuerName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pIssuerName)));
        i++;
    }

    if( sCertInfo.pSignAlgorithm )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignAlgorithm)));
        i++;
    }

    if( sCertInfo.pSignature )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignature)));
        i++;
    }

    if( pExtInfoList )
    {
        JExtensionInfoList *pCurList = pExtInfoList;

        while( pCurList )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i,0, new QTableWidgetItem(QString("%1").arg(pCurList->sExtensionInfo.pOID)));
            mFieldTable->setItem(i,1, new QTableWidgetItem(QString("%1%2")
                                                               .arg(pCurList->sExtensionInfo.bCritical ? "[C]" : "" )
                                                               .arg(pCurList->sExtensionInfo.pValue)));


            pCurList = pCurList->pNext;
            i++;
        }
    }

    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
}


void CertInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mFieldTable->clear();
    mFieldTable->horizontalHeader()->setStretchLastSection(true);
    mFieldTable->setColumnCount(2);
    mFieldTable->setHorizontalHeaderLabels( sBaseLabels );
    mFieldTable->verticalHeader()->setVisible(false);
    mFieldTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
}

void CertInfoDlg::clickField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mFieldTable->item( row, 1 );
    if( item == NULL ) return;

    mDetailText->setPlainText( item->text() );
}


void CertInfoDlg::clearTable()
{
    int rowCnt = mFieldTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mFieldTable->removeRow(0);
}
