#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "data_input_dlg.h"
#include "common.h"
#include "ber_applet.h"

DataInputDlg::DataInputDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clearData()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    connect( mDataText, SIGNAL(textChanged()), this, SLOT(changeData()));
    connect( mHexCheck, SIGNAL(clicked()), this, SLOT(changeData()));
    connect( mStringCheck, SIGNAL(clicked()), this, SLOT(changeData()));
    connect( mBase64Check, SIGNAL(clicked()), this, SLOT(changeData()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize( minimumSizeHint().width(), minimumSizeHint().height());
}

DataInputDlg::~DataInputDlg()
{

}

void DataInputDlg::initUI()
{
    mHexCheck->setChecked(true);
}

void DataInputDlg::setHead( const QString strLabel )
{
    mHeadLabel->setText( strLabel );
}

int DataInputDlg::getData( BIN *pData )
{
    int nType = DATA_STRING;
    QString strData = mDataText->toPlainText();

    if( mHexCheck->isChecked() )
    {
        nType = DATA_HEX;
    }
    else if( mBase64Check->isChecked() )
    {
        nType = DATA_BASE64;
    }
    else if( mStringCheck->isChecked() )
    {
        nType = DATA_STRING;
    }

    getBINFromString( pData, nType, strData );
}

void DataInputDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void DataInputDlg::dropEvent(QDropEvent *event)
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

    if( mHexCheck->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else if( mBase64Check->isChecked() )
    {
        JS_BIN_encodeBase64( &binData, &pOut );
    }
    else if( mStringCheck->isChecked() )
    {
        JS_BIN_string( &binData, &pOut );
    }

    if( pOut )
    {
        mDataText->setPlainText( pOut );
        JS_free( pOut );
    }

    JS_BIN_reset( &binData );
}

void DataInputDlg::changeData()
{
    int nType = DATA_STRING;
    QString strData = mDataText->toPlainText();

    if( mHexCheck->isChecked() )
    {
        nType = DATA_HEX;
        if( strData.length() < 1 )
            mDataText->setPlaceholderText( tr( "Hex value" ));
    }
    else if( mBase64Check->isChecked() )
    {
        nType = DATA_BASE64;

        if( strData.length() < 1 )
            mDataText->setPlaceholderText( tr( "Base64 value" ));
    }
    else if( mStringCheck->isChecked() )
    {
        nType = DATA_STRING;
        if( strData.length() < 1 )
            mDataText->setPlaceholderText( tr( "String value" ));
    }

    QString strLen = getDataLenString( nType, strData );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void DataInputDlg::clearData()
{
    mDataText->clear();
}

void DataInputDlg::clickOK()
{
    accept();
}
