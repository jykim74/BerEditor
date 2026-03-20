#include <QPrinter>
#include <QPainter>
#include <QPrintDialog>
#include <QPrintPreviewDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDateTime>

#include "bin_view_dlg.h"
#include "common.h"
#include "ber_applet.h"

const QStringList kHeaderList = {
    JS_PEM_NAME_RSA_PRIVATE_KEY,
    JS_PEM_NAME_RSA_PUBLIC_KEY,
    JS_PEM_NAME_CSR,
    JS_PEM_NAME_CERTIFICATE,
    JS_PEM_NAME_CRL,
    JS_PEM_NAME_PRIVATE_KEY,
    JS_PEM_NAME_PUBLIC_KEY,
    JS_PEM_NAME_ENCRYPTED_PRIVATE_KEY,
    JS_PEM_NAME_EC_PUBLIC_KEY,
    JS_PEM_NAME_EC_PARAMETERS,
    JS_PEM_NAME_EC_PRIVATE_KEY,
    JS_PEM_NAME_DSA_PRIVATE_KEY,
    JS_PEM_NAME_DSA_PUBLIC_KEY,
    JS_PEM_NAME_DSA_PARAMETERS,
    JS_PEM_NAME_PKCS7,
    JS_PEM_NAME_CMS,
    JS_PEM_NAME_DH_PARAMETERS
};

const int kBlockSize = 80;

BinViewDlg::BinViewDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    initUI();

    memset( &data_, 0x00, sizeof(BIN));

    connect( mBase64Radio, SIGNAL(clicked()), this, SLOT(checkBase64()));
    connect( mHexRadio, SIGNAL(clicked()), this, SLOT(checkHex()));
    connect( mRawRadio, SIGNAL(clicked()), this, SLOT(checkRaw()));
    connect( mPEMHeaderCheck, SIGNAL(clicked()), this, SLOT(checkPEM()));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPrintBtn, SIGNAL(clicked()), this, SLOT(clickPrint()));
    connect( mPrintPreviewBtn, SIGNAL(clicked()), this, SLOT(clickPrintPreview()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

BinViewDlg::~BinViewDlg()
{
    JS_BIN_reset( &data_ );
}

void BinViewDlg::initUI()
{
    mHeaderCombo->addItems( kHeaderList );
}

void BinViewDlg::initialize()
{
    mBase64Radio->setChecked(true);
    checkBase64();
}

void BinViewDlg::setData( const BIN *pData )
{
    JS_BIN_reset( &data_ );
    JS_BIN_copy( &data_, pData );
}

void BinViewDlg::log( const QString strLog, QColor cr )
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

void BinViewDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void BinViewDlg::dropEvent(QDropEvent *event)
{
    char *pOut = NULL;

    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            JS_BIN_reset( &data_ );
            JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &data_ );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void BinViewDlg::clickPrint()
{
    QPrinter printer;
    QPrintDialog dialog( &printer, this );

    if (dialog.exec() == QDialog::Accepted) {
        QPainter painter(&printer);
        this->render(&painter);   // QDialog 내용 출력
    }
}

void BinViewDlg::clickPrintPreview()
{
    QPrinter printer;

    QPrintPreviewDialog preview(&printer, this);
    preview.exec();
}

void BinViewDlg::clickFind()
{

}

void BinViewDlg::checkBase64()
{
    mAddressCheck->setEnabled( false );
    mASCIICheck->setEnabled( false );

    mPEMHeaderCheck->setEnabled( true );
    mHeaderCombo->setEnabled( true );

    checkPEM();
}

void BinViewDlg::checkHex()
{
    mAddressCheck->setEnabled( true );
    mASCIICheck->setEnabled( true );

    mPEMHeaderCheck->setEnabled( false );
    mHeaderCombo->setEnabled( false );
}

void BinViewDlg::checkRaw()
{
    mAddressCheck->setEnabled( false );
    mASCIICheck->setEnabled( false );

    mPEMHeaderCheck->setEnabled( false );
    mHeaderCombo->setEnabled( false );
}

void BinViewDlg::checkPEM()
{
    bool bVal = mPEMHeaderCheck->isChecked();

    mHeaderCombo->setEnabled( bVal );
}

void BinViewDlg::encodeBase64()
{

}

void BinViewDlg::encodeHex()
{
    if( mRawRadio->isChecked() == true )
    {
        mDataText->setPlainText( getHexString( &data_ ));
    }
    else
    {
        int nLeft = data_.nLen;
        int nSize = kBlockSize;
        int nPos = 0;
        BIN binPart = {0,0};

        while( nLeft > 0 )
        {
            QString strLine;

            if( nLeft > kBlockSize )
                nSize = kBlockSize;
            else
                nSize = nLeft;

            binPart.nLen = nSize;
            binPart.pVal = &data_.pVal[nPos];

            if( mAddressCheck->isChecked() )
            {
                strLine = QString( "0x%1 | " ).arg( nPos );
            }

            strLine += getHexString( &binPart );

            if( mASCIICheck->isChecked() )
            {
                char *pDump = NULL;
                JS_BIN_dumpString( &binPart, &pDump );

                strLine += QString( " | %1" ).arg( pDump );
                if( pDump ) JS_free( pDump );
            }

            log( strLine );

            nLeft -= nSize;
            nPos += nSize;
        }
    }
}

void BinViewDlg::encodeData()
{
    if( mBase64Radio->isChecked() == true )
        encodeBase64();
    else
        encodeHex();
}
