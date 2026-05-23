#include "ocsp_rsp_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "common.h"
#include "cert_info_dlg.h"

#include "js_ocsp.h"
#include "js_pki.h"
#include "js_util.h"

OCSPRspDlg::OCSPRspDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &rsp_, 0x00, sizeof(BIN));
    memset( &signer_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mViewSignerBtn, SIGNAL(clicked()), this, SLOT(clickViewSigner()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));
    connect( mInfoTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickInfoTable()));
    connect( mRspTree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), this, SLOT(clickRspTree()));

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
#endif

    initialize();
}

OCSPRspDlg::~OCSPRspDlg()
{
    JS_BIN_reset( &rsp_ );
    JS_BIN_reset( &signer_ );
}

void OCSPRspDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(sBaseLabels.size());
    mInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mInfoTable->verticalHeader()->setVisible(false);
    mInfoTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mRspTree->clear();
    mRspTree->header()->setVisible( false );
    mRspTree->setColumnCount(1);

    QTreeWidgetItem* root = new QTreeWidgetItem;
    root->setText( 0, "CertID List" );
    mRspTree->insertTopLevelItem( 0, root );
}

void OCSPRspDlg::initialize()
{

}

void OCSPRspDlg::setResponse( const BIN *pResp )
{
    int i = 0;
    int ret = 0;

    BIN binSignCert = {0,0};
    char sRevokedTime[64];
    QString strVerify;
    int nCount = 0;

    JOCSPSingleList *pRspList = NULL;
    JOCSPSingleList *pCurList = NULL;

    JOCSPRspInfo sRspInfo;

    memset( &sRspInfo, 0x00, sizeof(sRspInfo));

    JS_BIN_copy( &rsp_, pResp );

    ret = JS_OCSP_decodeResponse2( &rsp_, &binSignCert, 0, &sRspInfo, &pRspList );

    if( ret == JSR_VERIFY )
    {
        strVerify = tr("Verify OK");
    }
    else if( ret == JSR_INVALID )
    {
        strVerify = tr( "Verify Fail: %1").arg( JERR(ret));
    }
    else
    {
        strVerify = tr("Error: %1").arg( JERR(ret));
    }

    if( sRspInfo.binSigner.nLen > 0 )
    {
        JS_BIN_copy( &signer_, &sRspInfo.binSigner );
        mViewSignerBtn->setEnabled( true );
    }
    else
    {
        mViewSignerBtn->setEnabled( false );
    }

    nCount = JS_OCSP_countSingleRspList( pRspList );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i, 10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr( "Verify" )));
    mInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( strVerify )));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i, 10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr( "Rsp Count" )));
    mInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( nCount )));
    i++;

    char sDateTime[64];
    JS_UTIL_getDateTime( sRspInfo.tProduced, sDateTime );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i, 10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr( "Produced At" )));
    mInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sDateTime )));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i, 10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr( "Algorithm" )));
    mInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sRspInfo.pSignAlg )));
    i++;

    pCurList = pRspList;
    QTreeWidgetItem* rootItem = mRspTree->topLevelItem(0);

    while( pCurList )
    {
        QTreeWidgetItem* nameItem = new QTreeWidgetItem;
        nameItem->setText( 0, tr( "NameHash: %1" ).arg( pCurList->singleRsp.pNameHash ) );
        nameItem->setIcon( 0, QIcon(":/images/hash.png" ));

        rootItem->addChild( nameItem );

        if( pCurList->singleRsp.pHash )
        {
            QTreeWidgetItem* item = new QTreeWidgetItem;
            item->setText(0, tr( "Algorithm: %1" ).arg( pCurList->singleRsp.pHash ));
            item->setIcon( 0, QIcon(":/images/nemo.png"));
            nameItem->addChild( item );
        }

        if( pCurList->singleRsp.pKeyHash )
        {
            QTreeWidgetItem* item = new QTreeWidgetItem;
            item->setText(0, tr( "KeyHash: %1" ).arg( pCurList->singleRsp.pKeyHash ) );
            item->setIcon( 0, QIcon(":/images/nemo.png"));
            nameItem->addChild( item );
        }

        if( pCurList->singleRsp.pSerial )
        {
            QTreeWidgetItem* item = new QTreeWidgetItem;
            item->setText(0, tr("Serial: %1").arg( pCurList->singleRsp.pSerial ) );
            item->setIcon( 0, QIcon(":/images/nemo.png"));
            nameItem->addChild( item );
        }

        if( pCurList->singleRsp.nStatus >= 0 )
        {
            QTreeWidgetItem* statusItem = new QTreeWidgetItem;
            statusItem->setText( 0, tr("Status: %1").arg( JS_OCSP_getCertStatusName(pCurList->singleRsp.nStatus) ) );


            nameItem->addChild( statusItem );

            if( pCurList->singleRsp.nStatus != JS_OCSP_CERT_STATUS_GOOD )
            {
                statusItem->setIcon( 0, QIcon(":/images/revoke.png" ));

                QTreeWidgetItem* reasonItem = new QTreeWidgetItem;
                reasonItem->setText( 0, tr("Reason: %1").arg( JS_OCSP_getRevokeReasonName(pCurList->singleRsp.nReason) ) );
                reasonItem->setIcon( 0, QIcon(":/images/circle.png" ));
                statusItem->addChild( reasonItem );

                JS_UTIL_getDateTime( pCurList->singleRsp.tRevokedTime, sRevokedTime );
                QTreeWidgetItem* revokedTimeItem = new QTreeWidgetItem;
                revokedTimeItem->setText( 0, tr("RevokedTime: %1" ).arg( sRevokedTime ) );
                revokedTimeItem->setIcon( 0, QIcon(":/images/circle.png" ));
                statusItem->addChild( revokedTimeItem );

                if( pCurList->singleRsp.pHoldOID != NULL )
                {
                    QTreeWidgetItem* holdItem = new QTreeWidgetItem;
                    holdItem->setText( 0, tr( "Hold OID: %1" ).arg( pCurList->singleRsp.pHoldOID ) );
                    holdItem->setIcon( 0, QIcon(":/images/circle.png" ));
                    statusItem->addChild( holdItem );
                }
            }
            else
            {
                statusItem->setIcon( 0, QIcon(":/images/valid.png" ));
            }
        }

        pCurList = pCurList->pNext;
    }

    mRspTree->expandAll();

end :
    JS_BIN_reset( &binSignCert );

    JS_OCSP_resetOCSPInfo( &sRspInfo );
    if( pRspList ) JS_OCSP_resetSingleRspList( &pRspList );
}

void OCSPRspDlg::clickViewSigner()
{
    CertInfoDlg certInfo;
    certInfo.setCertBIN( &signer_, "OCSP Signer" );
    certInfo.exec();
}

void OCSPRspDlg::clickDecode()
{
    berApplet->decodeData( &rsp_ );
}

void OCSPRspDlg::clickInfoTable()
{
    mInfoText->clear();

    QModelIndex idx = mInfoTable->currentIndex();
    QTableWidgetItem* item = mInfoTable->item(idx.row(), 0 );
    QTableWidgetItem* item1 = mInfoTable->item( idx.row(), 1 );

    if( item == nullptr ) return;

    QString strField = item->text();
    QString strValue = item1->text();

    mInfoText->setPlainText( QString( "%1:%2" ).arg( strField ).arg( strValue) );
}

void OCSPRspDlg::clickRspTree()
{
    mInfoText->clear();

    QTreeWidgetItem* item = mRspTree->currentItem();
    if( item == nullptr ) return;

    QString strText = item->text(0);
    mInfoText->setPlainText( strText );
}
