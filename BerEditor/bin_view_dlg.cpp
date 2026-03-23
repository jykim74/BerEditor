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
#include "mainwindow.h"

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

const int kBlockSize = 64;

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
    connect( mAddressCheck, SIGNAL(clicked()), this, SLOT(checkAddress()));
    connect( mASCIICheck, SIGNAL(clicked()), this, SLOT(checkASCII()));
    connect( mHeaderCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeHeader()));
//    connect( mHeaderCombo, SIGNAL(editTextChanged(QString)), this, SLOT(changeHeader()));
    connect( mHeaderCombo, SIGNAL(currentTextChanged(QString)), this, SLOT(changeHeader()));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPrintBtn, SIGNAL(clicked()), this, SLOT(clickPrint()));
    connect( mPrintPreviewBtn, SIGNAL(clicked()), this, SLOT(filePrintPreview()));
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
    mHeaderCombo->addItem( "" );
    mHeaderCombo->addItems( kHeaderList );

    mHeaderCombo->setEditable(true);
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
    encodeData();
}

void BinViewDlg::log( const QString strLog, bool bNL )
{
    QTextCursor cursor = mDataText->textCursor();

    QTextCharFormat format;
    cursor.mergeCharFormat(format);

    if( bNL == true )
        cursor.insertText( QString( "%1\n" ).arg(strLog) );
    else
        cursor.insertText( strLog );

    mDataText->setTextCursor( cursor );
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
            setWindowTitle( tr( "Binary View - %1").arg( url.toLocalFile() ));
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
        mDataText->print(&printer);
        this->render(&painter);   // QDialog 내용 출력
    }
}

void BinViewDlg::printPreview(QPrinter *printer)
{
#ifdef QT_NO_PRINTER
    Q_UNUSED(printer);
#else
    mDataText->print( printer );
#endif
}

void BinViewDlg::filePrintPreview()
{
#if QT_CONFIG(printpreviewdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintPreviewDialog preview(&printer, this);
    connect(&preview, &QPrintPreviewDialog::paintRequested, this, &BinViewDlg::printPreview);
    preview.exec();
#endif
}

void BinViewDlg::clickFind()
{
    QString strPath = berApplet->curFilePath();

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BIN, strPath );

    if( strFileName > 0 )
    {
        JS_BIN_reset( &data_ );
        JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &data_ );

        setWindowTitle( tr( "Binary View - %1").arg( strFileName ));

        encodeData();
    }
}

void BinViewDlg::checkBase64()
{
    mAddressCheck->setEnabled( false );
    mASCIICheck->setEnabled( false );

    mPEMHeaderCheck->setEnabled( true );

    mHeaderCombo->setEnabled( mPEMHeaderCheck->isChecked() );

    encodeData();
}

void BinViewDlg::checkHex()
{
    mAddressCheck->setEnabled( true );
    mASCIICheck->setEnabled( true );

    mPEMHeaderCheck->setEnabled( false );
    mHeaderCombo->setEnabled( false );

    encodeData();
}

void BinViewDlg::checkRaw()
{
    mAddressCheck->setEnabled( false );
    mASCIICheck->setEnabled( false );

    mPEMHeaderCheck->setEnabled( false );
    mHeaderCombo->setEnabled( false );

    encodeData();
}

void BinViewDlg::checkAddress()
{
    encodeData();
}

void BinViewDlg::checkASCII()
{
    encodeData();
}

void BinViewDlg::changeHeader()
{
    QString strHeader = mHeaderCombo->currentText();

    if( strHeader.length() <= 1 ) return;

    encodeData();
}

void BinViewDlg::checkPEM()
{
    bool bVal = mPEMHeaderCheck->isChecked();

    mHeaderCombo->setEnabled( bVal );

    encodeData();
}

void BinViewDlg::encodeBase64()
{
    char *pBase64 = NULL;

    if( data_.nLen <= 0 ) return;

    QString strHeader = mHeaderCombo->currentText().toUpper();

    JS_BIN_encodeBase64NL( &data_, &pBase64, kBlockSize );
    if( pBase64 == NULL ) return;

    int len = strlen( pBase64 );

    if( len > 2 )
    {
        if( pBase64[len-1] == '\r' || pBase64[len-1] == '\n' )
            pBase64[len-1] = 0x00;

        if( pBase64[len-2] == '\r' || pBase64[len-2] == '\n' )
            pBase64[len-2] = 0x00;
    }


    if( mPEMHeaderCheck->isChecked() )
        log( QString( "-----BEGIN %1-----\r").arg( strHeader ));

    log( pBase64, false );

    if( mPEMHeaderCheck->isChecked() )
        log( QString( "-----END %1-----\r").arg( strHeader));

    if( pBase64 ) JS_free( pBase64 );
}

void BinViewDlg::encodeHex()
{
    if( data_.nLen <= 0 ) return;

    if( mRawRadio->isChecked() == true )
    {
        mDataText->setPlainText( getHexString( &data_ ));
    }
    else
    {
        int nLeft = data_.nLen;
        int nSize = 16;
        int nPos = 0;
        BIN binPart = {0,0};

        while( nLeft > 0 )
        {
            QString strLine;

            if( nLeft > 16 )
                nSize = 16;
            else
                nSize = nLeft;

            binPart.nLen = nSize;
            binPart.pVal = &data_.pVal[nPos];

            if( mAddressCheck->isChecked() )
            {
                strLine = QString( "%1 | " ).arg( nPos, 6, 16, QLatin1Char('0') );
            }

            strLine += QString( "%1" ).arg( getHexString2( &binPart ), -48, QLatin1Char(' ') );

            if( mASCIICheck->isChecked() )
            {
                char *pDump = NULL;
                JS_BIN_dumpString( &binPart, &pDump );

                strLine += QString( "| %1" ).arg( pDump );
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
    mDataText->clear();

    if( mBase64Radio->isChecked() == true )
        encodeBase64();
    else
        encodeHex();

    mDataText->moveCursor( QTextCursor::Start );
}
