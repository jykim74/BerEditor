#include <QTableView>

#include "ber_applet.h"
#include "mainwindow.h"
#include "tst_info_dlg.h"
#include "settings_mgr.h"

#include "js_bin.h"
#include "js_tsp.h"
#include "js_util.h"


TSTInfoDlg::TSTInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    memset( &tst_, 0x00, sizeof(BIN));

    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInfoTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
    connect( mDataDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDataDecode()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataDecodeBtn->setFixedWidth(34);
#endif

    initUI();
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TSTInfoDlg::~TSTInfoDlg()
{
    JS_BIN_reset( &tst_ );
}

void TSTInfoDlg::initialize()
{
    int i = 0;
    int ret = 0;

    JTSTInfo    sTSTInfo;
    QString strAccuracy;
    QString strMsgImprint;
    char    sGenTime[32];

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    clearTable();

    ret = JS_TSP_decodeTSTInfo( &tst_, &sTSTInfo );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to decode TST message [%1]").arg(ret), this );
        this->hide();
        return;
    }


    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("Version") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nVersion + 1)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("Order") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nOrder)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("Serial") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nSerial)));
    i++;

    JS_UTIL_getDateTime( sTSTInfo.tGenTime, sGenTime );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("GenTime") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sGenTime)));
    i++;

    if( sTSTInfo.pPolicy )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr( "Policy" ))));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pPolicy)));
        i++;
    }

    if( sTSTInfo.pGenName )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("GenName") )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pGenName)));
        i++;
    }

    if( sTSTInfo.pNonce )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("Nonce") )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pNonce)));
        i++;
    }


    strAccuracy = QString( tr("Sec:%1 millis:%2 micro:%3") )
                      .arg( sTSTInfo.sAccuracy.nSec )
                      .arg( sTSTInfo.sAccuracy.nMiliSec )
                      .arg( sTSTInfo.sAccuracy.nMicroSec );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("Accuracy") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strAccuracy)));
    i++;


    strMsgImprint = QString( "%1|%2")
                        .arg( sTSTInfo.sMsgImprint.pAlg )
                        .arg( sTSTInfo.sMsgImprint.pImprint );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString( tr("MsgImprint") )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strMsgImprint)));
    i++;

end :
    JS_TSP_resetTSTInfo( &sTSTInfo );
}

void TSTInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void TSTInfoDlg::clickField( QModelIndex index )
{
    int row = index.row();
    QTableWidgetItem *item0 = mInfoTable->item( row, 0 );
    QTableWidgetItem* item1 = mInfoTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    mDataText->setPlainText( item1->text() );
}

void TSTInfoDlg::clickDataDecode()
{
    berApplet->decodeData( &tst_, "TST" );
}

void TSTInfoDlg::setTST( const BIN *pTST )
{
    if( pTST == NULL ) return;

    JS_BIN_reset( &tst_ );
    JS_BIN_copy( &tst_, pTST );
}

void TSTInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(2);
    mInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mInfoTable->verticalHeader()->setVisible(false);
    mInfoTable->horizontalHeader()->setStyleSheet( style );
    mInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void TSTInfoDlg::clearTable()
{
    int rowCnt = mInfoTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mInfoTable->removeRow(0);
}
