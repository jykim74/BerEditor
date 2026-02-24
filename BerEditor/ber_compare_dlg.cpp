#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

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
    setAcceptDrops( true );

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mAFindBtn, SIGNAL(clicked()), this, SLOT(clickFindA()));
    connect( mBFindBtn, SIGNAL(clicked()), this, SLOT(clickFindB()));
    connect( mADecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecodeA()));
    connect( mBDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecodeB()));
    connect( mCompareBtn, SIGNAL(clicked()), this, SLOT(clickCompare()));
    connect( mShowDataBtn, SIGNAL(clicked()), this, SLOT(clickShowData()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mAGroup->layout()->setSpacing(5);
    mAGroup->layout()->setMargin(5);

    mBGroup->layout()->setSpacing(5);
    mBGroup->layout()->setMargin(5);

    mADecodeBtn->setFixedWidth(34);
    mBDecodeBtn->setFixedWidth(34);

    mInfoDock->layout()->setSpacing(5);
    mInfoDock->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

BERCompareDlg::~BERCompareDlg()
{
    if( modelA_ ) delete modelA_;
    if( modelB_ ) delete modelB_;
}

void BERCompareDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void BERCompareDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            BIN binBER = {0,0};

            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            if( mAPathText->text().length() < 1 )
            {
                mAPathText->setText( url.toLocalFile() );
                JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binBER );
                makeTreeA( &binBER );
                JS_BIN_reset( &binBER );
                break;
            }

            if( mBPathText->text().length() < 1 )
            {
                mBPathText->setText( url.toLocalFile() );
                JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binBER );
                makeTreeB( &binBER );
                JS_BIN_reset( &binBER );
                break;
            }

            berApplet->warningBox( tr( "Both files A and B already exist"), this );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void BERCompareDlg::clickShowData()
{
    mInfoDock->show();
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

int BERCompareDlg::compare( BerItem *pA, BerItem *pB )
{
    BIN binA = {0,0};
    BIN binB = {0,0};

    if( pA == NULL && pB == NULL )
        return BER_IS_SAME;

    if( pA == NULL || pB == NULL )
        return BER_NOT_SAME;

    if( pA->header_[0] != pB->header_[0] )
        return BER_TAG_DIFF;

    if( pA->level_ != pB->level_ )
        return BER_DEPTH_DIFF;

//    if( memcmp( pA->header_, pB->header_, pA->header_size_ ) != 0 )
//        return BER_HEAD_DIFF;

    if( pA->length_ != pB->length_ )
        return BER_VALUE_DIFF;

    modelA_->getValue( pA, &binA );
    modelB_->getValue( pB, &binB );

    if( JS_BIN_cmp( &binA, &binB ) == 0 )
    {
        JS_BIN_reset( &binA );
        JS_BIN_reset( &binB );
        return BER_IS_SAME;
    }
    else
    {
        JS_BIN_reset( &binA );
        JS_BIN_reset( &binB );

        return BER_VALUE_DIFF;
    }
}

void BERCompareDlg::clickFindA()
{
    BIN binBER = {0,0};
    QString strPath = mAPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mAPathText->setText( fileName );
    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binBER );

    makeTreeA( &binBER );
    JS_BIN_reset( &binBER );
}


void BERCompareDlg::clickFindB()
{
    BIN binBER = {0,0};
    QString strPath = mBPathText->text();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.isEmpty() ) return;

    mBPathText->setText( fileName );
    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binBER );

    makeTreeB( &binBER );
    JS_BIN_reset( &binBER );
}

void BERCompareDlg::makeTreeA( const BIN *pBER )
{
    if( pBER == NULL || pBER->nLen < 1 )
        return;

    modelA_->setBER( pBER );
    modelA_->makeTree( berApplet->settingsMgr()->autoExpand() );

    mStatusLabel->setText( tr( "Compare A and B" ));
}

void BERCompareDlg::makeTreeB( const BIN *pBER )
{
    if( pBER == NULL || pBER->nLen < 1 )
        return;

    modelB_->setBER( pBER );
    modelB_->makeTree( berApplet->settingsMgr()->autoExpand() );

    mStatusLabel->setText( tr( "Compare A and B" ));
}

void BERCompareDlg::clickDecodeA()
{
    BIN binBER = {0,0};

    QString strPath = mAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find A file"), this );
        mAPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binBER );

    berApplet->decodeData( &binBER, strPath );
    JS_BIN_reset( &binBER );
}

void BERCompareDlg::clickDecodeB()
{
    BIN binBER = {0,0};

    QString strPath = mBPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find B file"), this );
        mBPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binBER );

    berApplet->decodeData( &binBER, strPath );
    JS_BIN_reset( &binBER );
}

void BERCompareDlg::clickClear()
{
    mAPathText->clear();
    mBPathText->clear();

    modelA_->clearView();
    modelB_->clearView();

    mAText->clear();
    mBText->clear();
}

void BERCompareDlg::clickCompare()
{
    int ret = 0;
    BerItem *berItem = new BerItem;
    berItem->setText( "Text" );

    BIN binA = {0,0};
    BIN binB = {0,0};

    bool bSame = true;

    binA = modelA_->getBER();
    binB = modelB_->getBER();

    if( binA.nLen <= 0 )
    {
        berApplet->warningBox( tr( "Find A file" ), this );
        mAPathText->setFocus();
        return;
    }

    if( binB.nLen <= 0 )
    {
        berApplet->warningBox( tr( "Find B file" ), this );
        mBPathText->setFocus();
        return;
    }

    BerItem* itemA = modelA_->getNext( NULL );
    BerItem* itemB = modelB_->getNext( NULL );

    modelA_->setAllColor( Qt::darkRed );
    modelB_->setAllColor( Qt::darkRed );

    if( JS_BIN_cmp( &binA, &binB ) == 0 )
    {
        modelA_->setAllColor( Qt::blue );
        modelB_->setAllColor( Qt::blue );
    }
    else
    {
        while( itemA != nullptr )
        {
            ret = compare( itemA, itemB );

            if( ret == BER_IS_SAME )
            {
                if( itemA ) modelA_->setItemColor( itemA, Qt::blue );
                if( itemB ) modelA_->setItemColor( itemB, Qt::blue );
            }
            else
            {
                bSame = false;
            }

            itemA = modelA_->getNext( itemA );
            if( itemA )
            {
                if( mSETSortCheck->isChecked() == true )
                {
                    QList<BerItem *> listParent = modelA_->getParentList( itemA );
                    itemB = findItemB( listParent );
                }
                else
                {
                    QStringList listPos = modelA_->getPositon( itemA );
                    itemB = modelB_->findItemByPostion( listPos );
                }
            }
        }
    }

    if( bSame == true )
    {
        mStatusLabel->setStyleSheet( "QLabel { color : blue; }" );
        mStatusLabel->setText( tr("A and B are the same") );
    }
    else
    {
        mStatusLabel->setStyleSheet( "QLabel { color : darkRed; }" );
        mStatusLabel->setText( tr( "A and B are different" ) );
    }
}

void BERCompareDlg::clickNodeA()
{
    int ret = 0;
    BIN binValA = {0,0};
    BIN binValB = {0,0};

    BerItem *itemA = modelA_->getCurrentItem();
    BerItem *itemB = nullptr;
    QColor cr = Qt::darkRed;

    mAText->clear();
    modelA_->getCurrentValue( &binValA );


    if( mSETSortCheck->isChecked() == true )
    {
        QList<BerItem *> listParent = modelA_->getParentList( itemA );
        itemB = findItemB( listParent );
    }
    else
    {
        QStringList listPos = modelA_->getPositon( itemA );
        itemB = modelB_->findItemByPostion( listPos );
    }

    ret = compare( itemA, itemB );

    if( ret == BER_IS_SAME )
    {
        cr = Qt::blue;
    }

    logA( QString( "Tag: %1 Length: %2 Depth: %3\n")
             .arg( getHexString( itemA->header_, 1 ))
             .arg( getHexString( &itemA->header_[1], itemA->header_size_ - 1))
             .arg( itemA->GetLevel()), cr);

    logA( QString( "-------------------------------------\n"), cr );
    logValA( &binValA, cr );

    mBText->clear();
    modelB_->clearSelection();

    if( itemB )
    {
        if( ret == BER_IS_SAME || ret == BER_VALUE_DIFF )
        {
            modelB_->setSelectItem( itemB );
            modelB_->getValue( itemB, &binValB );
            logB( QString( "Tag: %1 Length: %2 Depth: %3\n")
                     .arg( getHexString( itemB->header_, 1 ))
                     .arg( getHexString( &itemB->header_[1], itemB->header_size_ - 1))
                     .arg( itemB->GetLevel()), cr);
            logB( QString( "-------------------------------------\n"), cr );
            logValB( &binValB, cr );
        }
    }

    JS_BIN_reset( &binValA );
    JS_BIN_reset( &binValB );
}

void BERCompareDlg::clickNodeB()
{
    int ret = 0;
    BIN binValA = {0,0};
    BIN binValB = {0,0};

    BerItem *itemB = modelB_->getCurrentItem();
    BerItem *itemA = nullptr;
    QColor cr = Qt::darkRed;

    mBText->clear();
    modelB_->getCurrentValue( &binValB );

    if( mSETSortCheck->isChecked() == true )
    {
        QList<BerItem *> listParent = modelB_->getParentList( itemB );
        itemA = findItemA( listParent );
    }
    else
    {
        QStringList listPos = modelB_->getPositon( itemB );
        itemA = modelA_->findItemByPostion( listPos );
    }

    ret = compare( itemA, itemB );

    if( ret == BER_IS_SAME )
    {
        cr = Qt::blue;
    }

    logB( QString( "Tag: %1 Length: %2 Depth: %3\n")
             .arg( getHexString( itemB->header_, 1 ))
             .arg( getHexString( &itemB->header_[1], itemB->header_size_ - 1))
             .arg( itemB->GetLevel()), cr);

    logB( QString( "-------------------------------------\n"), cr );
    logValB( &binValB, cr );

    mAText->clear();
    modelA_->clearSelection();

    if( itemA )
    {
        if( ret == BER_IS_SAME || ret == BER_VALUE_DIFF )
        {
            modelA_->setSelectItem( itemA );
            modelA_->getValue( itemA, &binValA );
            logA( QString( "Tag: %1 Length: %2 Depth: %3\n")
                     .arg( getHexString( itemA->header_, 1 ))
                     .arg( getHexString( &itemA->header_[1], itemA->header_size_ - 1))
                     .arg( itemA->GetLevel()), cr);

            logA( QString( "-------------------------------------\n"), cr );
            logValA( &binValA, cr );
        }
    }

    JS_BIN_reset( &binValA );
    JS_BIN_reset( &binValB );
}

void BERCompareDlg::logA( const QString strLog, QColor cr )
{
    QTextCursor cursor = mAText->textCursor();
    //    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    //cursor.insertText( "\n" );

    mAText->setTextCursor( cursor );
    mAText->repaint();
}

void BERCompareDlg::logB( const QString strLog, QColor cr )
{
    QTextCursor cursor = mBText->textCursor();
    //    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    //cursor.insertText( "\n" );

    mBText->setTextCursor( cursor );
    mBText->repaint();
}

void BERCompareDlg::logValA( const BIN *pVal, QColor cr )
{
    if( pVal == NULL || pVal->nLen <= 0 ) return;

    int nLeft = pVal->nLen;
    int nWidth = 16;
    int nBlock = 0;
    int nPos = 0;

    BIN binPart = {0,0};

    while( nLeft > 0 )
    {
        if( nLeft > nWidth )
            nBlock = nWidth;
        else
            nBlock = nLeft;

        binPart.pVal = pVal->pVal + nPos;
        binPart.nLen = nBlock;


        logA( QString( "%1\n").arg( getHexString( &binPart )), cr );

        nPos += nBlock;
        nLeft -= nBlock;
    }
}

void BERCompareDlg::logValB( const BIN *pVal, QColor cr )
{
    if( pVal == NULL || pVal->nLen <= 0 ) return;

    int nLeft = pVal->nLen;
    int nWidth = 16;
    int nBlock = 0;
    int nPos = 0;

    BIN binPart = {0,0};

    while( nLeft > 0 )
    {
        if( nLeft > nWidth )
            nBlock = nWidth;
        else
            nBlock = nLeft;

        binPart.pVal = pVal->pVal + nPos;
        binPart.nLen = nBlock;


        logB( QString( "%1\n").arg( getHexString( &binPart )), cr );

        nPos += nBlock;
        nLeft -= nBlock;
    }
}

BerItem* BERCompareDlg::findItemB( QList<BerItem *> itemAList )
{
    int ret = 0;
    BerItem *itemA = nullptr;
    BerItem *itemB = modelB_->getNext( NULL );
    BerItem *parent = nullptr;

    for( int i = 0; i < itemAList.size(); i++ )
    {
        itemA = itemAList.at(i);
        if( itemB == nullptr ) return nullptr;

        if( parent )
        {
            if( parent->isType( JS_SET ) )
            {
                int nChildCnt = parent->rowCount();
                for( int k = 0; k < nChildCnt; k++ )
                {
                    itemB = (BerItem *)parent->child( k, 0 );

                    ret = compare( itemA, itemB );
                    if( ret == BER_IS_SAME || ret == BER_VALUE_DIFF )
                    {
                        break;
                    }
                }
            }
            else
            {
                itemB = (BerItem *)parent->child( itemA->row(), 0 );
                ret = compare( itemA, itemB );
            }
        }
        else
        {
            ret = compare( itemA, itemB );
        }

        if( ret != BER_IS_SAME && ret != BER_VALUE_DIFF )
            return nullptr;

        parent = itemB;
    }

end :

    return itemB;
}

BerItem* BERCompareDlg::findItemA( QList<BerItem *> itemBList )
{
    int ret = 0;
    BerItem *itemB = nullptr;
    BerItem *itemA = modelA_->getNext( NULL );
    BerItem *parent = nullptr;

    for( int i = 0; i < itemBList.size(); i++ )
    {
        itemB = itemBList.at(i);
        if( itemA == nullptr ) return nullptr;

        if( parent )
        {
            if( parent->isType( JS_SET ) )
            {
                int nChildCnt = parent->rowCount();
                for( int k = 0; k < nChildCnt; k++ )
                {
                    itemA = (BerItem *)parent->child( k, 0 );

                    ret = compare( itemA, itemB );
                    if( ret == BER_IS_SAME || ret == BER_VALUE_DIFF )
                    {
                        break;
                    }
                }
            }
            else
            {
                itemA = (BerItem *)parent->child( itemB->row(), 0 );
                ret = compare( itemA, itemB );
            }
        }
        else
        {
            ret = compare( itemA, itemB );
        }

        if( ret != BER_IS_SAME && ret != BER_VALUE_DIFF )
            return nullptr;

        parent = itemA;
    }

end :

    return itemA;
}
