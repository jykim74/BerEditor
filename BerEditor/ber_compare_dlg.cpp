#include "ber_compare_dlg.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "ber_model.h"

BERCompareDlg::BERCompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &binA, 0x00, sizeof(BIN));
    memset( &binB, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mAFindBtn, SIGNAL(clicked()), this, SLOT(clickFindA()));
    connect( mBFindBtn, SIGNAL(clicked()), this, SLOT(clickFindB()));
    connect( mCompareBtn, SIGNAL(clicked()), this, SLOT(clickCompare()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

BERCompareDlg::~BERCompareDlg()
{
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
}

void BERCompareDlg::initUI()
{

}

void BERCompareDlg::initialize()
{

}

void BERCompareDlg::clickFindA()
{
    QString strPath = mAPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mAPathText->setText( fileName );
}


void BERCompareDlg::clickFindB()
{
    QString strPath = mBPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mBPathText->setText( fileName );
}

void BERCompareDlg::clickClear()
{
    mAText->clear();
    mBText->clear();
    mATreeView->clear();
    mBTreeView->clear();
}

void BERCompareDlg::clickCompare()
{
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
}
