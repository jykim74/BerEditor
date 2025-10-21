#include "cert_id_dlg.h"
#include "common.h"
#include "js_ocsp.h"
#include "ber_applet.h"
#include "mainwindow.h"

#include "js_util.h"

CertIDDlg::CertIDDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    memset( &resp_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CertIDDlg::~CertIDDlg()
{
    JS_BIN_reset( &resp_ );
}

void CertIDDlg::setResponse( const BIN *pResp )
{
    int i = 0;
    int ret = 0;
    JCertIDInfo sIDInfo;
    JCertStatusInfo sStatusInfo;
    BIN binSignCert = {0,0};
    char sRevokedTime[64];

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    JS_BIN_copy( &resp_, pResp );

    ret = JS_OCSP_decodeResponse( &resp_, &binSignCert, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to decode OCSP response: %1").arg(ret));
        goto end;
    }

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Hash" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pHash )));
    i++;

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "NameHash" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pNameHash )));
    i++;

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "KeyHash" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pKeyHash )));
    i++;

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Serial" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pSerial )));
    i++;

    i = 0;
    mStatusTable->insertRow(i);
    mStatusTable->setRowHeight(i, 10);
    mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "Status" )));
    mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1(%2)" )
                                                         .arg( JS_OCSP_getCertStatusName(sStatusInfo.nStatus))
                                                         .arg( sStatusInfo.nStatus )));
    i++;

    if( sStatusInfo.nStatus != JS_OCSP_CERT_STATUS_GOOD )
    {
        mStatusTable->insertRow(i);
        mStatusTable->setRowHeight(i, 10);
        mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "Reason" )));
        mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1(%2)" )
                                                             .arg( JS_OCSP_getRevokeReasonName(sStatusInfo.nReason))
                                                             .arg( sStatusInfo.nReason )));
        i++;

        JS_UTIL_getDateTime( sStatusInfo.nRevokedTime, sRevokedTime );
        mStatusTable->insertRow(i);
        mStatusTable->setRowHeight(i, 10);
        mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "RevokedTime" )));
        mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sRevokedTime )));
        i++;

        if( sStatusInfo.pHoldOID != NULL )
        {
            mStatusTable->insertRow(i);
            mStatusTable->setRowHeight(i, 10);
            mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "HoldOID" )));
            mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sStatusInfo.pHoldOID )));
            i++;
        }
    }

end :
    JS_BIN_reset( &binSignCert );
    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
}

void CertIDDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mIDTable->clear();
    mIDTable->horizontalHeader()->setStretchLastSection(true);
    mIDTable->setColumnCount(sBaseLabels.size());
    mIDTable->setHorizontalHeaderLabels( sBaseLabels );
    mIDTable->verticalHeader()->setVisible(false);
    mIDTable->horizontalHeader()->setStyleSheet( kTableStyle );
//    mIDTable->setSelectionBehavior(QAbstractItemView::SelectRows);
//    mIDTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mStatusTable->clear();
    mStatusTable->horizontalHeader()->setStretchLastSection(true);
    mStatusTable->setColumnCount(sBaseLabels.size());
    mStatusTable->setHorizontalHeaderLabels( sBaseLabels );
    mStatusTable->verticalHeader()->setVisible(false);
    mStatusTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mStatusTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mStatusTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void CertIDDlg::initialize()
{

}
