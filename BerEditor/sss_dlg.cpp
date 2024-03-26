/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>

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

SSSDlg::SSSDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mClearResultBtn, SIGNAL(clicked()), this, SLOT(clickClearResult()));
    connect( mSplitBtn, SIGNAL(clicked()), this, SLOT(clickSplit()));
    connect( mJoinBtn, SIGNAL(clicked()), this, SLOT(clickJoin()));

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcChanged()));
    connect( mSrcText, SIGNAL(textChanged(const QString&)), this, SLOT(srcChanged()));
    connect( mJoinedText, SIGNAL(textChanged(const QString&)), this, SLOT(joinedChanged()));

    connect( mShareTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotShareList(QPoint)));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();
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

    int nLen = getDataLen( nInputType, mSrcText->text() );
    mSrcLenText->setText( QString("%1").arg(nLen));
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

    int nLen = getDataLen( nInputType, mJoinedText->text() );
    mJoinedLenText->setText( QString("%1").arg(nLen));
}

void SSSDlg::clickClearResult()
{
    int nRow = mShareTable->rowCount();

    for( int i = 0; i < nRow; i++ )
    {
        mShareTable->removeRow( nRow - 1 - i );
    }

    mJoinedText->clear();
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
    }

    mShareTable->insertRow(row);
    mShareTable->setRowHeight( row, 10 );
    mShareTable->setItem( row, 0, new QTableWidgetItem( QString( "%1").arg(row)));
    mShareTable->setItem( row, 1, new QTableWidgetItem( strValue ));

    mShareText->clear();
}

void SSSDlg::clickSplit()
{
    int ret = 0;
    int i = 0;
    int nShares = mSharesText->text().toInt();
    int nThreshold = mThresholdText->text().toInt();
    int nCount = 0;
    QString strSrc = mSrcText->text();

    BIN binSrc = {0,0};
    BINList *pShareList = NULL;
    BINList *pCurList = NULL;

    if( strSrc.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter source value" ), this );
        mSrcText->setFocus();
        return;
    }

    clickClearResult();
    getBINFromString( &binSrc, mSrcTypeCombo->currentText(), strSrc );

    if( binSrc.nLen < 8 )
    {
        berApplet->warningBox( tr( "Input value must be at least 8 bytes"), this );
        goto end;
    }




    ret = JS_PKI_splitKey( nShares, nThreshold, &binSrc, &pShareList );

    if( ret != 0 ) goto end;

    pCurList = pShareList;

    nCount = JS_BIN_countList( pCurList );

    berApplet->logLine();
    berApplet->log( "-- Split Key" );
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

end :
    JS_BIN_reset( &binSrc );
    if( pShareList ) JS_BIN_resetList( &pShareList );
}

void SSSDlg::clickJoin()
{
    int ret = 0;
    int nRow = mShareTable->rowCount();

    BINList *pShareList = NULL;
    BIN binKey = {0,0};
    char *pKeyVal = NULL;

    if( nRow < 1 ) return;

    berApplet->logLine();
    berApplet->log( "-- Join Key" );
    berApplet->logLine();

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

    ret = JS_PKI_joinKey( nRow, pShareList, &binKey );

    if( ret != 0 ) goto end;

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
    if( pShareList ) JS_BIN_resetList( &pShareList );
    if( pKeyVal ) JS_free( pKeyVal );
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

void SSSDlg::clickClearDataAll()
{
    clickClearResult();
    mSrcText->clear();
    mShareText->clear();
    mThresholdText->clear();
}
