#include "cert_id_dlg.h"
#include "common.h"
#include "js_ocsp.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "cert_info_dlg.h"

#include "js_util.h"

CertIDDlg::CertIDDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    memset( &resp_, 0x00, sizeof(BIN));
    memset( &signer_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewSignerBtn, SIGNAL(clicked()), this, SLOT(clickViewSigner()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CertIDDlg::~CertIDDlg()
{
    JS_BIN_reset( &resp_ );
    JS_BIN_reset( &signer_ );
}

void CertIDDlg::setResponse( const BIN *pResp )
{
    int i = 0;
    int ret = 0;
    JCertIDInfo sIDInfo;
    JCertStatusInfo sStatusInfo;
    BIN binSignCert = {0,0};
    BIN binSigner = {0,0};
    char sRevokedTime[64];
    QString strVerify;
    char sResMsg[1024];

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));
    memset( sResMsg, 0x00, sizeof(sResMsg));

    sStatusInfo.nStatus = -1;

    JS_BIN_copy( &resp_, pResp );

    ret = JS_OCSP_decodeResponse( &resp_, &binSignCert, 0, &sIDInfo, &sStatusInfo, &binSigner, sResMsg );

    if( ret == JSR_VERIFY )
    {
        strVerify = tr("Verify OK");
    }
    else
    {
        strVerify = tr("Error: %1(%2)").arg( JERR(ret)).arg( sResMsg );
    }

    if( binSigner.nLen > 0 )
    {
        JS_BIN_copy( &signer_, &binSigner );
        mViewSignerBtn->setEnabled( true );
    }
    else
    {
        mViewSignerBtn->setEnabled( false );
    }

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Verify" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( strVerify )));
    i++;

//    if( ret != JSR_VERIFY && ret != JSR_INVALID && ret != JSR_OCSP_NO_SIGNER_CERT )
//        goto end;

    if( sIDInfo.pHash )
    {
        mIDTable->insertRow(i);
        mIDTable->setRowHeight(i, 10);
        mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Hash" )));
        mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pHash )));
        i++;
    }

    if( sIDInfo.pNameHash )
    {
        mIDTable->insertRow(i);
        mIDTable->setRowHeight(i, 10);
        mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "NameHash" )));
        mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pNameHash )));
        i++;
    }

    if( sIDInfo.pKeyHash )
    {
        mIDTable->insertRow(i);
        mIDTable->setRowHeight(i, 10);
        mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "KeyHash" )));
        mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pKeyHash )));
        i++;
    }

    if( sIDInfo.pSerial )
    {
        mIDTable->insertRow(i);
        mIDTable->setRowHeight(i, 10);
        mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Serial" )));
        mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sIDInfo.pSerial )));
        i++;
    }

    if( sStatusInfo.nStatus >= 0 )
    {
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

            JS_UTIL_getDateTime( sStatusInfo.tRevokedTime, sRevokedTime );
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
    }

end :
    JS_BIN_reset( &binSignCert );
    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
    JS_BIN_reset( &binSigner );
}

void CertIDDlg::setResponse2( const BIN *pResp )
{
    int i = 0;
    int ret = 0;

    BIN binSignCert = {0,0};
    BIN binSigner = {0,0};
    char sRevokedTime[64];
    QString strVerify;
    int nCount = 0;

    JOCSPSingleList *pRspList = NULL;
    JOCSPSingleList *pCurList = NULL;

    JOCSPRspInfo sRspInfo;
    char sResMsg[1024];

    memset( &sRspInfo, 0x00, sizeof(sRspInfo));
    memset( sResMsg, 0x00, sizeof(sResMsg));

    JS_BIN_copy( &resp_, pResp );

    ret = JS_OCSP_decodeResponse2( &resp_, &binSignCert, 0, &sRspInfo, &pRspList, sResMsg );

    if( ret == JSR_VERIFY )
    {
        strVerify = tr("Verify OK");
    }
    else
    {
        strVerify = tr("Error: %1").arg( JERR(ret) ).arg( sResMsg );
    }

    if( binSigner.nLen > 0 )
    {
        JS_BIN_copy( &signer_, &binSigner );
        mViewSignerBtn->setEnabled( true );
    }
    else
    {
        mViewSignerBtn->setEnabled( false );
    }

    nCount = JS_OCSP_countSingleRspList( pRspList );

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Verify" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( strVerify )));
    i++;

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Rsp Count" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( nCount )));
    i++;

    char sDateTime[64];
    JS_UTIL_getDateTime( sRspInfo.tProduced, sDateTime );

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Produced At" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sDateTime )));
    i++;

    mIDTable->insertRow(i);
    mIDTable->setRowHeight(i, 10);
    mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Algorithm" )));
    mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sRspInfo.pSignAlg )));
    i++;

    pCurList = pRspList;

    while( pCurList )
    {
        if( pCurList->singleRsp.pHash )
        {
            mIDTable->insertRow(i);
            mIDTable->setRowHeight(i, 10);
            mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Hash" )));
            mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( pCurList->singleRsp.pHash )));
            i++;
        }

        if( pCurList->singleRsp.pNameHash )
        {
            mIDTable->insertRow(i);
            mIDTable->setRowHeight(i, 10);
            mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "NameHash" )));
            mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( pCurList->singleRsp.pNameHash )));
            i++;
        }

        if( pCurList->singleRsp.pKeyHash )
        {
            mIDTable->insertRow(i);
            mIDTable->setRowHeight(i, 10);
            mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "KeyHash" )));
            mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( pCurList->singleRsp.pKeyHash )));
            i++;
        }

        if( pCurList->singleRsp.pSerial )
        {
            mIDTable->insertRow(i);
            mIDTable->setRowHeight(i, 10);
            mIDTable->setItem( i, 0, new QTableWidgetItem( tr( "Serial" )));
            mIDTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( pCurList->singleRsp.pSerial )));
            i++;
        }

        if( pCurList->singleRsp.nStatus >= 0 )
        {
            i = 0;
            mStatusTable->insertRow(i);
            mStatusTable->setRowHeight(i, 10);
            mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "Status" )));
            mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1(%2)" )
                                                             .arg( JS_OCSP_getCertStatusName(pCurList->singleRsp.nStatus))
                                                             .arg( pCurList->singleRsp.nStatus )));
            i++;

            if( pCurList->singleRsp.nStatus != JS_OCSP_CERT_STATUS_GOOD )
            {
                mStatusTable->insertRow(i);
                mStatusTable->setRowHeight(i, 10);
                mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "Reason" )));
                mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1(%2)" )
                                                                 .arg( JS_OCSP_getRevokeReasonName(pCurList->singleRsp.nReason))
                                                                 .arg( pCurList->singleRsp.nReason )));
                i++;

                JS_UTIL_getDateTime( pCurList->singleRsp.tRevokedTime, sRevokedTime );
                mStatusTable->insertRow(i);
                mStatusTable->setRowHeight(i, 10);
                mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "RevokedTime" )));
                mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sRevokedTime )));
                i++;

                if( pCurList->singleRsp.pHoldOID != NULL )
                {
                    mStatusTable->insertRow(i);
                    mStatusTable->setRowHeight(i, 10);
                    mStatusTable->setItem( i, 0, new QTableWidgetItem( tr( "HoldOID" )));
                    mStatusTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( pCurList->singleRsp.pHoldOID )));
                    i++;
                }
            }
        }

        pCurList = pCurList->pNext;
    }

end :
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binSigner );

    JS_OCSP_resetOCSPInfo( &sRspInfo );
    if( pRspList ) JS_OCSP_resetSingleRspList( &pRspList );
}

void CertIDDlg::clickViewSigner()
{
    CertInfoDlg certInfo;
    certInfo.setCertBIN( &signer_, "OCSP Signer" );
    certInfo.exec();
}

void CertIDDlg::clickDecode()
{
    berApplet->decodeData( &resp_ );
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
    mIDTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIDTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

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
