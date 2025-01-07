/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include <QRegExpValidator>
#include <QValidator>

#include "js_pki.h"
#include "js_sss.h"
#include "sss_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList primeBits = {
    "8", "16", "32", "64", "128", "256"
};

SSSDlg::SSSDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clearShareTable()));
    connect( mSplitBtn, SIGNAL(clicked()), this, SLOT(clickSplit()));
    connect( mJoinBtn, SIGNAL(clicked()), this, SLOT(clickJoin()));

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcChanged()));
    connect( mSrcText, SIGNAL(textChanged(const QString&)), this, SLOT(srcChanged()));
    connect( mJoinedText, SIGNAL(textChanged(const QString&)), this, SLOT(joinedChanged()));

    connect( mShareTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotShareList(QPoint)));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mMakePrimeBtn, SIGNAL(clicked()), this, SLOT(clickMakePrime()));
    connect( mPrimeText, SIGNAL(textChanged(QString)), this, SLOT(changePrime(QString)));
    connect( mShareText, SIGNAL(textChanged(QString)), this, SLOT(changeShare(QString)));

    connect( mSrcClearBtn, SIGNAL(clicked()), this, SLOT(clearSrc()));
    connect( mPrimeClearBtn, SIGNAL(clicked()), this, SLOT(clearPrime()));
    connect( mJoinedClearBtn, SIGNAL(clicked()), this, SLOT(clearJoined()));

    initialize();
    mSplitBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mInfoTab->layout()->setSpacing(5);
    mInfoTab->layout()->setMargin(5);

    mSrcClearBtn->setFixedWidth(34);
    mPrimeClearBtn->setFixedWidth(34);
    mJoinedClearBtn->setFixedWidth(34);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SSSDlg::~SSSDlg()
{

}

void SSSDlg::initialize()
{
    mSharesText->setText( "5" );
    mThresholdText->setText( "3" );

    QStringList headerList = { tr( "Seq"), tr( "Value") };

    mSrcTypeCombo->addItems( dataTypes );
    mJoinedTypeCombo->addItems( dataTypes );

    mShareTable->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    mShareTable->horizontalHeader()->setStyleSheet( style );

    mShareTable->setColumnCount(headerList.size());
    mShareTable->setHorizontalHeaderLabels( headerList );
    mShareTable->verticalHeader()->setVisible(false);
//    mShareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
//    mShareTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mShareTable->setColumnWidth(0, 40);

    QRegExp regExp("^[0-9a-fA-F]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mPrimeText->setValidator( regVal );

    mPrimeBitsCombo->addItems( primeBits );
    mPrimeBitsCombo->setEditable( true );

    mShareText->setValidator( regVal );
}

void SSSDlg::srcChanged()
{
    int nInputType = 0;

    if( mSrcTypeCombo->currentText() == "String" )
        nInputType = DATA_STRING;
    else if( mSrcTypeCombo->currentText() == "Hex" )
        nInputType = DATA_HEX;
    else if( mSrcTypeCombo->currentText() == "Base64" )
        nInputType = DATA_BASE64;
    else
        nInputType = DATA_HEX;

    QString strLen = getDataLenString( nInputType, mSrcText->text() );
    mSrcLenText->setText( QString("%1").arg(strLen));
}

void SSSDlg::joinedChanged()
{
    int nInputType = 0;

    if( mJoinedTypeCombo->currentText() == "String" )
        nInputType = DATA_STRING;
    else if( mJoinedTypeCombo->currentText() == "Hex" )
        nInputType = DATA_HEX;
    else if( mJoinedTypeCombo->currentText() == "Base64" )
        nInputType = DATA_BASE64;
    else
        nInputType = DATA_HEX;

    QString strLen = getDataLenString( nInputType, mJoinedText->text() );
    mJoinedLenText->setText( QString("%1").arg(strLen));
}


void SSSDlg::clickAdd()
{
    QString strValue = mShareText->text();

    if( strValue.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter shared value" ), this );
        mShareText->setFocus();
        return;
    }

    int row = mShareTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mShareTable->item( i, 1 );
        if( item->text() == strValue )
        {
            berApplet->warningBox( tr( "%1 is already added").arg( strValue ), this );
            return;
        }

        if( item->text().length() != strValue.length() )
        {
            berApplet->warningBox( tr( "All inputs must have the same length."), this );
            return;
        }
    }

    mShareTable->insertRow(row);
    mShareTable->setRowHeight( row, 10 );
    mShareTable->setItem( row, 0, new QTableWidgetItem( QString( "%1").arg(row + 1)));
    mShareTable->setItem( row, 1, new QTableWidgetItem( strValue ));

    mShareText->clear();
}

void SSSDlg::clickSplit()
{
    int ret = 0;
    int i = 0;
    int nShares = mSharesText->text().toInt();
    int nThreshold = mThresholdText->text().toInt();

    QString strSrc = mSrcText->text();

    BIN binSrc = {0,0};
    BINList *pShareList = NULL;
    BINList *pCurList = NULL;
    BIN binPrime = {0,0};

    if( strSrc.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter source value" ), this );
        mSrcText->setFocus();
        return;
    }

    clearShareTable();
    getBINFromString( &binSrc, mSrcTypeCombo->currentText(), strSrc );
    JS_BIN_decodeHex( mPrimeText->text().toStdString().c_str(), &binPrime );

    berApplet->logLine();
    berApplet->log( "-- Split Key" );
    berApplet->log( QString( "Prime Value : %1").arg( getHexString( &binPrime )));

    if( binSrc.nLen < 8 )
    {
        berApplet->warningBox( tr( "Input value must be at least 8 bytes"), this );
        mSrcText->setFocus();
        goto end;
    }

    if( binSrc.nLen > binPrime.nLen )
    {
        berApplet->warningBox( tr( "Prime value ​​must be longer than or equal to the source value" ), this );
        mPrimeText->setFocus();
        goto end;
    }

//    ret = JS_PKI_splitKey( nShares, nThreshold, &binSrc, &pShareList );
    ret = JS_PKI_splitKey2( nShares, nThreshold, &binPrime, &binSrc, &pShareList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to split key: %1").arg(ret), this );
        goto end;
    }

    pCurList = pShareList;


    berApplet->logLine();
    berApplet->log( QString( "Src Key Value   : %1").arg( getHexString( &binSrc )));
    while( pCurList )
    {
        QString strVal = getHexString( pCurList->Bin.pVal, pCurList->Bin.nLen );
        mShareTable->insertRow(i);

        mShareTable->setRowHeight( i, 10 );
        mShareTable->setItem( i, 0, new QTableWidgetItem( QString( "%1").arg(i)));
        mShareTable->setItem( i, 1, new QTableWidgetItem( strVal ));

        berApplet->log( QString( "Split Key Value : %1").arg( getHexString(&pCurList->Bin)));

        pCurList = pCurList->pNext;
        i++;
    }

    berApplet->logLine();
 //   OpenSSL_SSS_Test();

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPrime );
    if( pShareList ) JS_BIN_resetList( &pShareList );
}

void SSSDlg::clickJoin()
{
    int ret = 0;
    int nRow = mShareTable->rowCount();
    QString strPrime = mPrimeText->text();

    BINList *pShareList = NULL;
    BIN binKey = {0,0};
    BIN binPrime = {0,0};
    char *pKeyVal = NULL;

    if( nRow < 2 )
    {
        berApplet->warningBox( tr( "Two or more shared values ​​are required" ), this );
        mShareText->setFocus();
        return;
    }

    if( strPrime.length() < 1 )
    {
        berApplet->warningBox(tr("Enter a prime number" ), this );
        mPrimeText->setFocus();
        return;
    }

    berApplet->logLine();
    berApplet->log( "-- Join Key" );
    berApplet->logLine();

    JS_BIN_decodeHex( strPrime.toStdString().c_str(), &binPrime );
    berApplet->log( QString( "Prime Value : %1").arg( getHexString( &binPrime )));

    for( int i = 0; i < nRow; i++ )
    {
        BIN binVal = {0,0};
        QTableWidgetItem *item = mShareTable->item( i, 1 );
        if( item == NULL ) continue;

        QString strVal = item->text();
        JS_BIN_decodeHex( strVal.toStdString().c_str(), &binVal );
        berApplet->log( QString( "Joined Key Value : %1").arg( strVal ));

        JS_BIN_addList( &pShareList, &binVal );

        JS_BIN_reset( &binVal );
    }

    berApplet->logLine();

//    ret = JS_PKI_joinKey( nRow, pShareList, &binKey );
    ret = JS_PKI_joinKey2( nRow, &binPrime, pShareList, &binKey );

    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to join key: %1").arg(ret), this );
        goto end;
    }


    if( mJoinedTypeCombo->currentText() == "String" )
    {
        JS_BIN_string( &binKey, &pKeyVal );
    }
    else if( mJoinedTypeCombo->currentText() == "Hex" )
        JS_BIN_encodeHex( &binKey, &pKeyVal );
    else if( mJoinedTypeCombo->currentText() == "Base64" )
        JS_BIN_encodeBase64( &binKey, &pKeyVal );

    berApplet->log( QString( "Combined Key : %1").arg( getHexString( &binKey )));
    berApplet->logLine();

    mJoinedText->setText( pKeyVal );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binPrime );
    if( pShareList ) JS_BIN_resetList( &pShareList );
    if( pKeyVal ) JS_free( pKeyVal );
}

void SSSDlg::clickMakePrime()
{
    int nBytes = mPrimeBitsCombo->currentText().toInt();

    BIN binPrime = {0,0};
    JS_PKI_makePrime( nBytes * 8, &binPrime );

    mPrimeText->setText( getHexString( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void SSSDlg::changePrime( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mPrimeLenText->setText( QString("%1").arg( strLen ));
}

void SSSDlg::changeShare( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mShareLenText->setText( QString("%1").arg( strLen ));
}

void SSSDlg::slotShareList(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(delShare()));

    menu->addAction( delAct );
    menu->popup( mShareTable->viewport()->mapToGlobal(pos));
}

void SSSDlg::delShare()
{
    QModelIndex idx = mShareTable->currentIndex();
    mShareTable->removeRow( idx.row() );
}

void SSSDlg::clearShareTable()
{
    mShareTable->setRowCount(0);
}

void SSSDlg::clickClearDataAll()
{
    clearShareTable();

    mShareText->clear();
    mSharesText->clear();
    mThresholdText->clear();

    clearSrc();
    clearPrime();
    clearJoined();
}

void SSSDlg::clearSrc()
{
    mSrcText->clear();
}

void SSSDlg::clearPrime()
{
    mPrimeText->clear();
}
void SSSDlg::clearJoined()
{
    mJoinedText->clear();
}
