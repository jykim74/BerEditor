#include <QDialog>
#include <QLayout>

#include "cmp_info_dlg.h"
#include "js_cmp.h"
#include "js_cmp_srv.h"

#include "ber_applet.h"
#include "mainwindow.h"

CMPInfoDlg::CMPInfoDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &cmp_msg_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

CMPInfoDlg::~CMPInfoDlg()
{
    JS_BIN_reset( &cmp_msg_ );
}

void CMPInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mGenInfoTable->clear();
    mGenInfoTable->horizontalHeader()->setStretchLastSection(true);
    mGenInfoTable->setColumnCount(sBaseLabels.size());
    mGenInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mGenInfoTable->verticalHeader()->setVisible(false);
    mGenInfoTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mGenInfoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mGenInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mGenInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mDetailInfoTable->clear();
    mDetailInfoTable->horizontalHeader()->setStretchLastSection(true);
    mDetailInfoTable->setColumnCount(sBaseLabels.size());
    mDetailInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mDetailInfoTable->verticalHeader()->setVisible(false);
    mDetailInfoTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mDetailInfoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mDetailInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mDetailInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void CMPInfoDlg::initialize()
{

}

void CMPInfoDlg::setMsg( const BIN *pMsg )
{
    int i = 0;
    int ret = 0;
    JCMPGenInfo sInfo;
    void *pData = NULL;

    JS_BIN_reset( &cmp_msg_ );
    JS_BIN_copy( &cmp_msg_, pMsg );

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_CMP_getInfo( &cmp_msg_, &sInfo, &pData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get cmp message information: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    mGenInfoTable->insertRow(i);
    mGenInfoTable->setRowHeight(i,10);
    mGenInfoTable->setItem( i, 0, new QTableWidgetItem( "CMP Type" ));
    mGenInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( JS_CMP_typeName( sInfo.nType ) ) ));
    i++;

    if( sInfo.pProtectAlg )
    {
        mGenInfoTable->insertRow(i);
        mGenInfoTable->setRowHeight(i,10);
        mGenInfoTable->setItem( i, 0, new QTableWidgetItem( "Protection Alg" ));
        mGenInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( sInfo.pProtectAlg ) ));
        i++;
    }

    if( sInfo.binNonce.nLen > 0 )
    {
        mGenInfoTable->insertRow(i);
        mGenInfoTable->setRowHeight(i,10);
        mGenInfoTable->setItem( i, 0, new QTableWidgetItem( "Nonce" ));
        mGenInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( getHexString( &sInfo.binNonce) ) ));
        i++;
    }

    if( sInfo.binTransID.nLen > 0 )
    {
        mGenInfoTable->insertRow(i);
        mGenInfoTable->setRowHeight(i,10);
        mGenInfoTable->setItem( i, 0, new QTableWidgetItem( "TransID" ));
        mGenInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( getHexString( &sInfo.binTransID) ) ));
        i++;
    }

    if( sInfo.binSendKID.nLen > 0 )
    {
        mGenInfoTable->insertRow(i);
        mGenInfoTable->setRowHeight(i,10);
        mGenInfoTable->setItem( i, 0, new QTableWidgetItem( "SendKID" ));
        mGenInfoTable->setItem(i, 1, new QTableWidgetItem( QString( "%1" ).arg( getHexString( &sInfo.binSendKID) ) ));
        i++;
    }

    setCMPData( sInfo.nType, pData );

end :
    JS_CMP_resetGenInfo( &sInfo );
}

void CMPInfoDlg::setCMPData( int nType, void *pData )
{

}
