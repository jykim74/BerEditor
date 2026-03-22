#include <QPrinter>
#include <QPainter>
#include <QPrintDialog>
#include <QPrintPreviewDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDateTime>

#include "text_view_dlg.h"
#include "common.h"
#include "ber_applet.h"

#include "ber_model.h"
#include "ttlv_tree_model.h"
#include "ttlv_tree_item.h"
#include "settings_mgr.h"

#include "js_kms.h"

TextViewDlg::TextViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    initUI();

    memset( &data_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPrintBtn, SIGNAL(clicked()), this, SLOT(clickPrint()));
    connect( mPrintPreviewBtn, SIGNAL(clicked()), this, SLOT(filePrintPreview()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    connect( mCertUtilRadio, SIGNAL(clicked()), this, SLOT(checkCertUtil()));
    connect( mOpenSSLRadio, SIGNAL(clicked()), this, SLOT(checkOpenSSL()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TextViewDlg::~TextViewDlg()
{
    JS_BIN_reset( &data_ );
}

void TextViewDlg::initUI()
{
    mOpenSSLRadio->setChecked(true);
}

void TextViewDlg::setData( const BIN *pData )
{
    JS_BIN_reset( &data_ );
    JS_BIN_copy( &data_, pData );

    int ret = JS_KMS_isTTLV( &data_ );

    if( ret == 1 )
    {
        parseTTLV();
    }
    else
    {
        parseBER();
    }
}

void TextViewDlg::log( const QString strLog, bool bNL )
{
    QTextCursor cursor = mDataText->textCursor();

    QTextCharFormat format;
    cursor.mergeCharFormat(format);

    if( bNL == true )
        cursor.insertText( QString( "%1\n" ).arg(strLog) );
    else
        cursor.insertText( strLog );

    mDataText->setTextCursor( cursor );
    mDataText->repaint();
}

void  TextViewDlg::log( int nSpace, const QString strLog, bool bNL )
{
    QString strSpace;
    QTextCursor cursor = mDataText->textCursor();

    QTextCharFormat format;
    cursor.mergeCharFormat(format);

    if( bNL == true )
        cursor.insertText( QString( "%1%2\n" ).arg( strSpace, nSpace, QLatin1Char( ' ' )).arg(strLog) );
    else
        cursor.insertText( QString( "%1%2" ).arg( strSpace, nSpace, QLatin1Char( ' ' )).arg(strLog));

    mDataText->setTextCursor( cursor );
    mDataText->repaint();
}

void TextViewDlg::log( const QString strHead, int nSpace, const QString strValue, bool bNL )
{
    QString strSpace;
    QTextCursor cursor = mDataText->textCursor();

    QTextCharFormat format;
    cursor.mergeCharFormat(format);

    if( bNL == true )
        cursor.insertText( QString( "%1%2%3\n" ).arg( strHead ).arg( strSpace, nSpace, QLatin1Char( ' ' )).arg(strValue) );
    else
        cursor.insertText( QString( "%1%2%3" ).arg( strHead ).arg( strSpace, nSpace, QLatin1Char( ' ' )).arg(strValue));

    mDataText->setTextCursor( cursor );
    mDataText->repaint();
}

 void TextViewDlg::line()
{
    log( "==================================================================");
}

void TextViewDlg::logBIN( int nSpace, const BIN *pData )
{
    int nLeft = pData->nLen;
    int nPos = 0;
    int kBlockSize = 16;

    while( nLeft > 0 )
    {
        int nSize = 0;
        BIN binPart = {0,0};

        if( nLeft > kBlockSize )
            nSize = 16;
        else
            nSize = nLeft;

        binPart.pVal = &pData->pVal[nPos];
        binPart.nLen = nSize;

        log( nSpace, QString( "%1" ).arg( getHexString2(&binPart)));

        nPos += nSize;
        nLeft -= nSize;
    }
}

void TextViewDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void TextViewDlg::dropEvent(QDropEvent *event)
{
    char *pOut = NULL;

    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
//            JS_BIN_reset( &data_ );
//            JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &data_ );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void TextViewDlg::clickPrint()
{
    QPrinter printer;
    QPrintDialog dialog( &printer, this );

    if (dialog.exec() == QDialog::Accepted) {
        QPainter painter(&printer);
        mDataText->print(&printer);
        this->render(&painter);   // QDialog 내용 출력
    }
}

void TextViewDlg::printPreview(QPrinter *printer)
{
#ifdef QT_NO_PRINTER
    Q_UNUSED(printer);
#else
    mDataText->print( printer );
#endif
}

void TextViewDlg::filePrintPreview()
{
#if QT_CONFIG(printpreviewdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintPreviewDialog preview(&printer, this);
    connect(&preview, &QPrintPreviewDialog::paintRequested, this, &TextViewDlg::printPreview);
    preview.exec();
#endif
}

void TextViewDlg::clickFind()
{
    QString strPath = berApplet->curFilePath();

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BIN, strPath );

    if( strFileName > 0 )
    {
        JS_BIN_reset( &data_ );
        JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &data_ );

        int ret = JS_KMS_isTTLV( &data_ );

        if( ret == 1 )
        {
            parseTTLV();
        }
        else
        {
            parseBER();
        }

        setWindowTitle( tr( "Text View - %1").arg( strFileName ));
    }
}

void TextViewDlg::checkCertUtil()
{
    int ret = JS_KMS_isTTLV( &data_ );

    if( ret == 1 )
    {
        parseTTLV();
    }
    else
    {
        parseBER();
    }
}

void TextViewDlg::checkOpenSSL()
{
    int ret = JS_KMS_isTTLV( &data_ );

    if( ret == 1 )
    {
        parseTTLV();
    }
    else
    {
        parseBER();
    }
}

void TextViewDlg::parseBER()
{
    BerModel berModel;
    bool bExpand = berApplet->settingsMgr()->autoExpand();

    berModel.setBER( &data_ );
    berModel.parseTree( bExpand );

    mDataText->clear();

    if( mCertUtilRadio->isChecked() )
        textCertUtil( &berModel );
    else
        textOpenSSL( &berModel );

    mDataText->moveCursor( QTextCursor::Start );
}

void TextViewDlg::parseTTLV()
{
    TTLVTreeModel ttlvModel;

    ttlvModel.setTTLV( &data_ );
    ttlvModel.parseTree();

    TTLVTreeView* treeView = ttlvModel.getTreeView();

    mDataText->clear();

    if( mCertUtilRadio->isChecked() )
        textCertUtil( &ttlvModel );
    else
        textOpenSSL( &ttlvModel );

    mDataText->moveCursor( QTextCursor::Start );
}

void TextViewDlg::textCertUtil( BerModel *pModel )
{
    BerTreeView* treeView = pModel->getTreeView();
    BerItem *curItem = NULL;

    curItem = treeView->getNext( curItem );

    while( curItem )
    {
        QString strLine;
        int nLevel = curItem->GetLevel() * 2;

        BIN binHeader = {0,0};
        JS_BIN_set( &binHeader, curItem->header_, curItem->header_size_ );

        strLine += QString( "%1" ).arg( getHexString2( &binHeader ) );
        log( nLevel, strLine );

        if( curItem->isConstructed() == false )
        {
            BIN binVal = {0,0};
            binVal.pVal = &data_.pVal[curItem->offset_ + curItem->header_size_];
            binVal.nLen = curItem->length_;

            logBIN( nLevel, &binVal );
        }

        curItem = treeView->getNext( curItem );
        JS_BIN_reset( &binHeader );
    }
}

void TextViewDlg::textOpenSSL( BerModel *pModel )
{
    line();
    log( "| Offset | Depth | Length | Tag (Type)" );
    line();

    BerTreeView* treeView = pModel->getTreeView();
    BerItem *curItem = NULL;

    curItem = treeView->getNext( curItem );

    while( curItem )
    {
        QString strLine;
        int nDepth = curItem->GetLevel();

        QString strS = " ";
        if( nDepth == 0 ) strS = "";

        strLine = QString( "| %1 | %2 | %3 |%4 %5")
                      .arg( curItem->GetOffset(), 6, 10, QLatin1Char(' ') )
                      .arg( curItem->GetLevel(), 5, 10, QLatin1Char(' ') )
                      .arg( curItem->GetLength(), 6, 10, QLatin1Char(' ') )
                      .arg( strS, nDepth, QLatin1Char( ' '))
                      .arg( curItem->GetTagString() );

        log( strLine );

        curItem = treeView->getNext( curItem );
    }

    line();
}

void TextViewDlg::textCertUtil( TTLVTreeModel *pModel )
{
    TTLVTreeView* treeView = pModel->getTreeView();
    TTLVTreeItem *curItem = NULL;

    curItem = treeView->getNext( curItem );

    while( curItem )
    {
        QString strLine;

        strLine += getHexString( &curItem->header_ );

        log( strLine );
        curItem = treeView->getNext( curItem );
    }
}

void TextViewDlg::textOpenSSL( TTLVTreeModel *pModel )
{
    line();
    log( "| Offset | Depth | Length | Tag (Type)" );
    line();

    TTLVTreeView* treeView = pModel->getTreeView();
    TTLVTreeItem *curItem = NULL;

    curItem = treeView->getNext( curItem );

    while( curItem )
    {
        QString strLine;
        QString strS = " ";

        int nDepth = curItem->getLevel();
        if( nDepth == 0 ) strS = "";

        strLine = QString( "| %1 | %2 | %3 |%4 %5")
                      .arg( curItem->getOffset(), 6, 10, QLatin1Char(' ') )
                      .arg( curItem->getLevel(), 5, 10, QLatin1Char(' ') )
                      .arg( curItem->getLength(), 6, 10, QLatin1Char(' ') )
                      .arg( strS, nDepth, QLatin1Char( ' '))
                      .arg( curItem->getTagName() );

        log( strLine );

        curItem = treeView->getNext( curItem );
    }

    line();
}
