#include "ber_compare_dlg.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "ber_model.h"
#include "ber_item.h"

BERCompareDlg::BERCompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

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
    if( modelA_ ) delete modelA_;
    if( modelB_ ) delete modelB_;
}

void BERCompareDlg::initUI()
{
    // GroupBox Layout 설정
    modelA_ = new CompModel(this);
    modelB_ = new CompModel(this);

    connect( modelA_->getTreeView(), SIGNAL(clicked(QModelIndex)), this, SLOT(clickNodeA()));
    connect( modelB_->getTreeView(), SIGNAL(clicked(QModelIndex)), this, SLOT(clickNodeB()));

    mAGroup->setMinimumHeight( 300 );

    QVBoxLayout *ALayout = new QVBoxLayout();
    ALayout->addWidget( modelA_->getTreeView() );
    mAGroup->setLayout(ALayout);

    QVBoxLayout *BLayout = new QVBoxLayout();
    BLayout->addWidget( modelB_->getTreeView() );
    mBGroup->setLayout(BLayout);
}

void BERCompareDlg::initialize()
{

}

int BERCompareDlg::compare( const BerItem *pA, const BerItem *pB )
{
    if( pA == NULL && pB == NULL )
        return BER_IS_SAME;

    if( pA == NULL || pB == NULL )
        return BER_NOT_SAME;

    if( pA->header_[0] != pB->header_[0] )
        return BER_TAG_DIFF;

    if( pA->level_ != pB->level_ )
        return BER_DEPTH_DIFF;

    if( memcmp( pA->header_, pB->header_, pA->header_size_ ) != 0 )
        return BER_HEAD_DIFF;

    return BER_IS_SAME;
}

void BERCompareDlg::clickFindA()
{
    QString strPath = mAPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;


    mAPathText->setText( fileName );
    bool bSET = mSETSortCheck->isChecked();

    BIN binBER = {0,0};
    int ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binBER );
    if( ret > 0 )
    {
        modelA_->setBER( &binBER );
        modelA_->makeTree( bSET, false );
    }

    JS_BIN_reset( &binBER );
}


void BERCompareDlg::clickFindB()
{
    QString strPath = mBPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mBPathText->setText( fileName );
    bool bSET = mSETSortCheck->isChecked();

    BIN binBER = {0,0};
    int ret = JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binBER );
    if( ret > 0 )
    {
        modelB_->setBER( &binBER );
        modelB_->makeTree( bSET, false );
    }

    JS_BIN_reset( &binBER );
}

void BERCompareDlg::clickClear()
{
    mAText->clear();
    mBText->clear();
}

void BERCompareDlg::clickCompare()
{
    BerItem *berItem = new BerItem;
    berItem->setText( "Text" );
}

void BERCompareDlg::clickNodeA()
{
    mAText->setPlainText( "ClickA" );

    BIN binVal = {0,0};
    BerItem *item = modelA_->getCurrentItem();
    modelA_->getValue( &binVal );

    mAText->appendPlainText( getHexString( &binVal) );
    JS_BIN_reset( &binVal );

    QStringList listPos = modelA_->getPositon( item );

    for( int i = 0; i < listPos.size(); i++ )
    {
        QString strPos = listPos.at(i);
        mAText->appendPlainText( QString( "Pos: %1").arg( strPos ));
    }

    BerItem *find = modelB_->findItemByPostion( listPos );

    if( find )
    {
        mAText->appendPlainText( "Find" );
        modelB_->setSelectItem( find );
    }
    else
    {
        mAText->appendPlainText( "No item" );
    }
}

void BERCompareDlg::clickNodeB()
{
    mBText->setPlainText( "ClickB" );

    BIN binVal = {0,0};
    BerItem *item = modelB_->getCurrentItem();
    modelB_->getValue( &binVal );

    mBText->appendPlainText( getHexString( &binVal) );
    JS_BIN_reset( &binVal );

    mBText->appendPlainText( QString( "Row: %1 Level: %2").arg( item->row()).arg( item->GetLevel() ));
}
