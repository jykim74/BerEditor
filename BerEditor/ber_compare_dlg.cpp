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

    if( memcmp( pA->header_, pB->header_, pA->header_size_ ) != 0 )
        return BER_HEAD_DIFF;

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
    BerItem *berItem = new BerItem;
    berItem->setText( "Text" );
}

void BERCompareDlg::clickNodeA()
{
    BIN binVal = {0,0};
    BerItem *itemA = modelA_->getCurrentItem();
    modelA_->getCurrentValue( &binVal );

    mAText->appendPlainText( getHexString( &binVal) );
    JS_BIN_reset( &binVal );

    QStringList listPos = modelA_->getPositon( itemA );

    for( int i = 0; i < listPos.size(); i++ )
    {
        QString strPos = listPos.at(i);
        mAText->appendPlainText( QString( "Pos: %1").arg( strPos ));
    }

    BerItem *itemB = modelB_->findItemByPostion( listPos );

    if( itemB )
    {
        mAText->appendPlainText( "Find" );
        modelB_->setSelectItem( itemB );
    }
    else
    {
        mAText->appendPlainText( "No item" );
    }

    int ret = compare( itemA, itemB );
    mAText->appendPlainText( QString( "Compare: %1").arg(ret));
}

void BERCompareDlg::clickNodeB()
{
    BIN binVal = {0,0};
    BerItem *itemB = modelB_->getCurrentItem();
    modelB_->getCurrentValue( &binVal );

    mBText->appendPlainText( getHexString( &binVal) );
    JS_BIN_reset( &binVal );

    QStringList listPos = modelB_->getPositon( itemB );

    for( int i = 0; i < listPos.size(); i++ )
    {
        QString strPos = listPos.at(i);
        mBText->appendPlainText( QString( "Pos: %1").arg( strPos ));
    }

    BerItem *itemA = modelA_->findItemByPostion( listPos );

    if( itemA )
    {
        mBText->appendPlainText( "Find" );
        modelA_->setSelectItem( itemB );
    }
    else
    {
        mBText->appendPlainText( "No item" );
    }

    int ret = compare( itemA, itemB );
    mBText->appendPlainText( QString( "Compare: %1").arg(ret));
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
