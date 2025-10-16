/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "decode_data_dlg.h"
#include "ber_applet.h"
#include "common.h"

DecodeDataDlg::DecodeDataDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeData()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
    connect( mTypeHex, SIGNAL(clicked()), this, SLOT(dataChanged()));
    connect( mTypeBase64, SIGNAL(clicked()), this, SLOT(dataChanged()));
    connect( mTypeBase64URL, SIGNAL(clicked()), this, SLOT(dataChanged()));

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(findData()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clearData()));

    mTypeHex->setChecked(true);
    mDecodeBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize( minimumSizeHint().width(), minimumSizeHint().height());
}

DecodeDataDlg::~DecodeDataDlg()
{

}

void DecodeDataDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void DecodeDataDlg::dropEvent(QDropEvent *event)
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

    if( mTypeHex->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else if( mTypeBase64->isChecked() )
    {
        JS_BIN_encodeBase64( &binData, &pOut );
    }
    else if( mTypeBase64URL->isChecked() )
    {
        JS_BIN_encodeBase64URL( &binData, &pOut );
    }

    if( pOut )
    {
        mDataText->setPlainText( pOut );
        JS_free( pOut );
    }

    JS_BIN_reset( &binData );
}

void DecodeDataDlg::initUI()
{
    mDataText->setAcceptDrops(false);
    mDataText->setPlaceholderText( tr( "Hex value" ));
}

void DecodeDataDlg::decodeData()
{
    int nType = 0;
    BIN binData = {0,0};

    if( mTypeHex->isChecked() )
        nType = DATA_HEX;
    else if( mTypeBase64->isChecked() )
        nType = DATA_BASE64;
    else if( mTypeBase64URL->isChecked() )
        nType = DATA_BASE64URL;

    QString strData = mDataText->toPlainText();

    if( strData.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter data"), this );
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

    berApplet->decodeData( &binData );
    JS_BIN_reset( &binData );
    QDialog::accept();
}


QString DecodeDataDlg::getTextData()
{
    return mDataText->toPlainText();
}

void DecodeDataDlg::dataChanged()
{
    int nType = DATA_STRING;

    if( mTypeHex->isChecked() )
    {
        nType = DATA_HEX;
        mDataText->setPlaceholderText( tr( "Hex value" ));
    }
    else if( mTypeBase64->isChecked() )
    {
        nType = DATA_BASE64;
        mDataText->setPlaceholderText( tr( "Base64 or PEM value" ));
    }
    else if( mTypeBase64URL->isChecked() )
    {
        nType = DATA_BASE64URL;
        mDataText->setPlaceholderText( tr( "Base64URL value" ));
    }

    QString strLen = getDataLenString( nType, mDataText->toPlainText() );
    mDataLenText->setText( QString("%1").arg(strLen));
}

void DecodeDataDlg::clearData()
{
    mDataText->clear();
}

void DecodeDataDlg::findData()
{
    BIN binData = {0,0};
    QString strPath;
    char *pOut = NULL;

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( strFileName.length() < 1 ) return;

    JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binData );

    if( mTypeHex->isChecked() )
    {
        mDataText->setPlainText( getHexString( &binData ));
    }
    else if( mTypeBase64->isChecked() )
    {
        JS_BIN_encodeBase64( &binData, &pOut );
    }
    else if( mTypeBase64URL->isChecked() )
    {
        JS_BIN_encodeBase64URL( &binData, &pOut );
    }

    if( pOut )
    {
        mDataText->setPlainText( pOut );
        JS_free( pOut );
    }

    JS_BIN_reset( &binData );
}
