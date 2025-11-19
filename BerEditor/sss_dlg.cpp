/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include <QRegExpValidator>
#include <QValidator>
#include <QClipboard>

#include "js_pki.h"
#include "js_sss.h"
#include "js_bn.h"
#include "sss_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"

static QStringList primeBits = {
    "8", "16", "32", "64", "128", "256"
};

SSSDlg::SSSDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clearShareTable()));
    connect( mSplitBtn, SIGNAL(clicked()), this, SLOT(clickSplit()));
    connect( mJoinBtn, SIGNAL(clicked()), this, SLOT(clickJoin()));
    connect( mIsPrimeBtn, SIGNAL(clicked()), this, SLOT(clickIsPrime()));

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
    mSrcText->setFocus();

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

void SSSDlg::initUI()
{
    QRegExp regExp("^[0-9-]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    QRegExpValidator* regThres = new QRegExpValidator( regExp );

    mSharesText->setValidator( regVal );
    mThresholdText->setValidator( regVal );
}

void SSSDlg::initialize()
{
    mSharesText->setText( "5" );
    mThresholdText->setText( "3" );

    QStringList headerList = { tr( "Shared value") };

    mSrcTypeCombo->addItems( kDataTypeList );
    mJoinedTypeCombo->addItems( kDataTypeList );


    mShareTable->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    mShareTable->horizontalHeader()->setStyleSheet( style );

    mShareTable->setColumnCount(headerList.size());
    mShareTable->setHorizontalHeaderLabels( headerList );
    mShareTable->verticalHeader()->setVisible(false);
    mShareTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mShareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mShareTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mShareTable->setColumnWidth(0, 40);

    QRegExp regExp("^[0-9a-fA-F]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mPrimeText->setValidator( regVal );

    mPrimeBitsCombo->addItems( primeBits );
    mPrimeBitsCombo->setEditable( true );
    mPrimeBitsCombo->setCurrentText( "16" );

    mShareText->setValidator( regVal );

    mPrimeText->setPlaceholderText( tr( "Enter the prime number to use for SSS" ) );
    mShareText->setPlaceholderText( tr( "Enter the values ​​to combine" ));
    mSrcText->setPlaceholderText( tr( "Enter the key value to split" ) );
}

void SSSDlg::srcChanged()
{
    int nInputType = 0;

    if( mSrcTypeCombo->currentText() == "String" )
    {
        nInputType = DATA_STRING;
    }
    else if( mSrcTypeCombo->currentText() == "Hex" )
    {
        nInputType = DATA_HEX;
    }
    else if( mSrcTypeCombo->currentText() == "Base64" )
    {
        nInputType = DATA_BASE64;
    }
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

    if( strValue.length() < 4 )
    {
        berApplet->warningBox( tr( "You must enter at least 2 bytes (4 characters)" ), this );
        mShareText->setFocus();
        return;
    }

    int row = mShareTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mShareTable->item( i, 0 );
        if( item->text() == strValue )
        {
            berApplet->warningBox( tr( "%1 is already added").arg( strValue ), this );
            return;
        }
    }

    mShareTable->insertRow(0);
    mShareTable->setRowHeight( 0, 10 );
    mShareTable->setItem( 0, 0, new QTableWidgetItem( strValue ));

    mShareText->clear();
}

void SSSDlg::clickSplit()
{
    int ret = 0;
    int i = 0;
    int nShares = mSharesText->text().toInt();
    int nThreshold = mThresholdText->text().toInt();

    QString strSrc = mSrcText->text();
    QString strPrime = mPrimeText->text();

    BIN binSrc = {0,0};
    BINList *pShareList = NULL;
    BINList *pCurList = NULL;
    BIN binPrime = {0,0};

    if( mSharesText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a shared number" ), this );
        mSharesText->setFocus();
        return;
    }

    if( mThresholdText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a threshold" ), this );
        mThresholdText->setFocus();
        return;
    }

    if( strPrime.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a prime number" ), this );
        mPrimeText->setFocus();
        return;
    }

    if( strSrc.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter source value" ), this );
        mSrcText->setFocus();
        return;
    }

    clearShareTable();
    ret = getBINFromString( &binSrc, mSrcTypeCombo->currentText(), strSrc );
    FORMAT_WARN_GO(ret);

    ret = getBINFromString( &binPrime, DATA_HEX, mPrimeText->text() );
    FORMAT_WARN_GO(ret);

    if( binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr("There is no input value or the input type is incorrect."), this );
        mSrcText->setFocus();
        goto end;
    }

    berApplet->logLine();
    berApplet->log( "-- Split Key" );
    berApplet->logLine2();
    berApplet->log( QString( "Prime Value     : %1").arg( getHexString( &binPrime )));

    if( JS_BN_cmp( &binPrime, &binSrc ) <= 0 )
    {
        berApplet->warningBox( tr( "Prime value ​​must be greater to the source value" ), this );
        mPrimeText->setFocus();
        goto end;
    }

    ret = JS_PKI_splitKeyGF256( nShares, nThreshold, &binPrime, &binSrc, &pShareList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to split key: %1").arg(JERR(ret)), this );
        goto end;
    }

    pCurList = pShareList;


    berApplet->logLine();
    berApplet->log( QString( "Src Key Value   : %1").arg( getHexString( &binSrc )));
    while( pCurList )
    {
        QString strVal = getHexString( pCurList->Bin.pVal, pCurList->Bin.nLen );
        mShareTable->insertRow(0);

        mShareTable->setRowHeight( 0, 10 );
        mShareTable->setItem( 0, 0, new QTableWidgetItem( strVal ));

        berApplet->log( QString( "Split Key Value : %1").arg( getHexString(&pCurList->Bin)));

        pCurList = pCurList->pNext;
        i++;
    }

    berApplet->logLine();
    berApplet->messageBox( tr("Key splitting was successful"), this );

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
    QString strThresHold = mThresholdText->text();

    BINList *pShareList = NULL;
    BIN binKey = {0,0};
    BIN binPrime = {0,0};
    QString strKeyValue;

    if( strThresHold.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a threshold" ), this );
        mThresholdText->setFocus();
        return;
    }

    if( strPrime.length() < 1 )
    {
        berApplet->warningBox(tr("Enter a prime number" ), this );
        mPrimeText->setFocus();
        return;
    }

    if( nRow < 2 )
    {
        berApplet->warningBox( tr( "Two or more shared values ​​are required" ), this );
        mShareText->setFocus();
        return;
    }

    if( nRow < strThresHold.toInt() )
    {
        berApplet->warningBox( tr("%1 data are required").arg( strThresHold ), this );
        mShareText->setFocus();
        return;
    }

    berApplet->logLine();
    berApplet->log( "-- Join Key" );
    berApplet->logLine2();

    JS_BIN_decodeHex( strPrime.toStdString().c_str(), &binPrime );
    berApplet->log( QString( "Prime Value      : %1").arg( getHexString( &binPrime )));

    for( int i = 0; i < nRow; i++ )
    {
        BIN binVal = {0,0};
        QTableWidgetItem *item = mShareTable->item( i, 0 );
        if( item == NULL ) continue;

        QString strVal = item->text();
        JS_BIN_decodeHex( strVal.toStdString().c_str(), &binVal );
        berApplet->log( QString( "Joined Key Value : %1").arg( strVal ));

        JS_BIN_addList( &pShareList, &binVal );

        JS_BIN_reset( &binVal );
    }

    berApplet->logLine();

    ret = JS_PKI_joinKeyGF256( strThresHold.toInt(), &binPrime, pShareList, &binKey );

    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to join key: %1").arg(JERR(ret)), this );
        goto end;
    }

    strKeyValue = getStringFromBIN( &binKey, mJoinedTypeCombo->currentText() );

    berApplet->log( QString( "Combined Key     : %1").arg( getHexString( &binKey )));
    berApplet->logLine();

    mJoinedText->setText( strKeyValue );
    berApplet->messageBox( tr("Key join was successful"), this );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binPrime );
    if( pShareList ) JS_BIN_resetList( &pShareList );
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

    QAction *copyAct = new QAction( tr( "Copy" ), this );
    connect( copyAct, SIGNAL(triggered(bool)), this, SLOT(copyShare()));

    menu->addAction( delAct );
    menu->addAction( copyAct );

    menu->popup( mShareTable->viewport()->mapToGlobal(pos));
}

void SSSDlg::delShare()
{
    QModelIndex idx = mShareTable->currentIndex();
    mShareTable->removeRow( idx.row() );
}

void SSSDlg::copyShare()
{
    QModelIndex idx = mShareTable->currentIndex();
    QTableWidgetItem* item = mShareTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( item->text() );
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

void SSSDlg::clickIsPrime()
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strPrime = mPrimeText->text();
    QString strVal;

    if( strPrime.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert a prime value" ), this );
        mPrimeText->setFocus();
        return;
    }

    if( strPrime.length() % 2 )
    {
        strVal = "0";
    }

    strVal += strPrime;
    JS_BIN_decodeHex( strVal.toStdString().c_str(), &binVal );

    ret = JS_BN_isPrime( &binVal );

    if( ret == 1 )
        berApplet->messageLog( tr( "The value is prime"), this );
    else
        berApplet->warnLog( tr( "The value is not prime" ), this );

    JS_BIN_reset( &binVal );
}
