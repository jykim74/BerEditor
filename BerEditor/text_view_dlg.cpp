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

TextViewDlg::TextViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPrintBtn, SIGNAL(clicked()), this, SLOT(clickPrint()));
    connect( mPrintPreviewBtn, SIGNAL(clicked()), this, SLOT(clickPrintPreview()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

TextViewDlg::~TextViewDlg()
{

}

void TextViewDlg::log( const QString strLog, QColor cr )
{
    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    QTextCursor cursor = mDataText->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );
    cursor.insertText( strMsg );

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
        this->render(&painter);   // QDialog 내용 출력
    }
}

void TextViewDlg::clickPrintPreview()
{
    QPrinter printer;

    QPrintPreviewDialog preview(&printer, this);
    preview.exec();
}

void TextViewDlg::clickFind()
{

}
