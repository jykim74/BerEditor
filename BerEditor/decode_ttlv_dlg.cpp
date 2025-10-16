#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "decode_ttlv_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"


DecodeTTLVDlg::DecodeTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setAcceptDrops( true );

    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mHexRadio, SIGNAL(clicked()), this, SLOT(changeData()));
    connect( mBase64Radio, SIGNAL(clicked()), this, SLOT(changeData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(findData()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clearData()));

    initialize();
    mDecodeBtn->setDefault(true);
    mDataText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize( minimumSizeHint().width(), minimumSizeHint().height());
}

DecodeTTLVDlg::~DecodeTTLVDlg()
{

}

void DecodeTTLVDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void DecodeTTLVDlg::dropEvent(QDropEvent *event)
{
    BIN binData = {0,0};
    char *pOut = NULL;

    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binData );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }

    if( mHexRadio->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else if( mBase64Radio->isChecked() )
    {
        JS_BIN_encodeBase64( &binData, &pOut );
    }

    if( pOut )
    {
        mDataText->setPlainText( pOut );
        JS_free( pOut );
    }

    JS_BIN_reset( &binData );
}

void DecodeTTLVDlg::initialize()
{
    mDataText->setAcceptDrops(false);
    mHexRadio->setChecked(true);
}

void DecodeTTLVDlg::clickDecode()
{
    int nType = 0;
    BIN binData = {0,0};

    if( mHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strData = mDataText->toPlainText();

    if( strData.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter your data"), this );
        mDataText->setFocus();
        return;
    }

    getBINFromString( &binData, nType, strData );
    if( binData.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is an invalid character" ), this);
        mDataText->setFocus();
        return;
    }

    berApplet->decodeTTLV( &binData );

    JS_BIN_reset( &binData );
    QDialog::accept();
}

void DecodeTTLVDlg::changeData()
{
    int nType = 0;

    if( mHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void DecodeTTLVDlg::clearData()
{
    mDataText->clear();
}

void DecodeTTLVDlg::findData()
{
    BIN binData = {0,0};
    QString strPath;

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BIN, strPath );
    if( strFileName.length() < 1 ) return;

    JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binData );
    if( mHexRadio->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else
    {
        char *pBase64 = NULL;
        JS_BIN_encodeBase64( &binData, &pBase64 );

        if( pBase64 )
        {
            mDataText->setPlainText( pBase64 );
            JS_free( pBase64 );
        }
    }

    JS_BIN_reset( &binData );
}

