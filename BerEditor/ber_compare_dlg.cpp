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


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mADecodeBtn->setFixedWidth(34);
    mBDecodeBtn->setFixedWidth(34);
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
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            if( mAPathText->text().length() < 1 )
            {
                mAPathText->setText( url.toLocalFile() );
                break;
            }

            if( mBPathText->text().length() < 1 )
            {
                mBPathText->setText( url.toLocalFile() );
                break;
            }

            berApplet->warningBox( tr( "Both files A and B already exist"), this );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
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

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );

    return BER_NOT_SAME;
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
        modelA_->makeTree( berApplet->settingsMgr()->autoExpand() );

        mStatusLabel->setText( tr( "A and B status" ));
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
        modelB_->makeTree( berApplet->settingsMgr()->autoExpand() );

        mStatusLabel->setText( tr( "A and B status" ));
    }

    JS_BIN_reset( &binBER );
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

    logA( QString( "TL : %1\n").arg( getHexString( itemA->header_, itemA->header_size_ )), cr);
    logA( QString( "Value : %1").arg( getHexString( &binValA)), cr );

    mBText->clear();
    modelB_->clearSelection();

    if( itemB )
    {
        modelB_->setSelectItem( itemB );
        modelB_->getValue( itemB, &binValB );
        logB( QString( "TL : %1\n").arg( getHexString( itemB->header_, itemB->header_size_ )), cr);
        logB( QString( "Value : %1").arg( getHexString( &binValB)), cr );
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

    logB( QString( "TL : %1\n").arg( getHexString( itemB->header_, itemB->header_size_ )), cr);
    logB( QString( "Value : %1").arg( getHexString( &binValB)), cr );

    mAText->clear();
    modelA_->clearSelection();

    if( itemA )
    {
        modelA_->setSelectItem( itemA );
        modelA_->getValue( itemA, &binValA );
        logA( QString( "TL : %1\n").arg( getHexString( itemA->header_, itemA->header_size_ )), cr);
        logA( QString( "Value : %1").arg( getHexString( &binValA)), cr );
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
