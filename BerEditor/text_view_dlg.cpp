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

#include "js_kms.h"

TextViewDlg::TextViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    memset( &data_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPrintBtn, SIGNAL(clicked()), this, SLOT(clickPrint()));
    connect( mPrintPreviewBtn, SIGNAL(clicked()), this, SLOT(filePrintPreview()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TextViewDlg::~TextViewDlg()
{
    JS_BIN_reset( &data_ );
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

        setData( &data_ );
    }
}

void TextViewDlg::parseBER()
{
    BerModel berModel;

    berModel.setBER( &data_ );
    berModel.makeTree( false );

    BerTreeView* treeView = berModel.getTreeView();

    if( mCertUtilRadio->isChecked() )
        textCertUtil( &berModel );
    else
        textOpenSSL( &berModel );
}

void TextViewDlg::parseTTLV()
{
    TTLVTreeModel ttlvModel;

    ttlvModel.setTTLV( &data_ );
    ttlvModel.parseTree();

    TTLVTreeView* treeView = ttlvModel.getTreeView();

    if( mCertUtilRadio->isChecked() )
        textCertUtil( &ttlvModel );
    else
        textOpenSSL( &ttlvModel );
}

void TextViewDlg::textCertUtil( BerModel *pModel )
{

}

void TextViewDlg::textOpenSSL( BerModel *pModel )
{

}

void TextViewDlg::textCertUtil( TTLVTreeModel *pModel )
{

}

void TextViewDlg::textOpenSSL( TTLVTreeModel *pModel )
{

}
