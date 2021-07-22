#include <QMenu>

#include "js_pki.h"
#include "js_sss.h"
#include "sss_dlg.h"
#include "common.h"

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
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mSplitBtn, SIGNAL(clicked()), this, SLOT(clickSplit()));
    connect( mJoinBtn, SIGNAL(clicked()), this, SLOT(clickJoin()));

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(srcChanged()));
    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(srcChanged()));

    connect( mShareTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotShareList(QPoint)));

    initialize();
}

SSSDlg::~SSSDlg()
{

}

void SSSDlg::initialize()
{
    mNText->setText( "5" );
    mKText->setText( "3" );

    QStringList headerList = { tr( "Seq"), tr( "Value") };

    mSrcTypeCombo->addItems( dataTypes );
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

    int nLen = getDataLen( nInputType, mSrcText->toPlainText() );
    mSrcLenText->setText( QString("%1").arg(nLen));
}

void SSSDlg::clickClear()
{
    int nRow = mShareTable->rowCount();

    for( int i = 0; i < nRow; i++ )
    {
        mShareTable->removeRow( nRow - 1 - i );
    }
}

void SSSDlg::clickAdd()
{
    QString strValue = mShareText->text();
    int row = mShareTable->rowCount();

    if( strValue.length() > 0 )
    {
       mShareTable->insertRow(row);
       mShareTable->setRowHeight( row, 10 );
       mShareTable->setItem( row, 0, new QTableWidgetItem( QString( "%1").arg(row)));
       mShareTable->setItem( row, 1, new QTableWidgetItem( strValue ));

       mShareText->clear();
    }
}

void SSSDlg::clickSplit()
{
    int ret = 0;
    int i = 0;
    int nN = mNText->text().toInt();
    int nK = mKText->text().toInt();
    int nCount = 0;
    QString strSrc = mSrcText->toPlainText();

    BIN binSrc = {0,0};
    BINList *pShareList = NULL;
    BINList *pCurList = NULL;

    if( strSrc.isEmpty() ) return;

    clickClear();

    if( mSrcTypeCombo->currentText() == "String" )
        JS_BIN_set( &binSrc, (unsigned char *)strSrc.toStdString().c_str(), strSrc.length() );
    else if( mSrcTypeCombo->currentText() == "Hex" )
        JS_BIN_decodeHex( strSrc.toStdString().c_str(), &binSrc );
    else if( mSrcTypeCombo->currentText() == "Base64" )
        JS_BIN_decodeBase64( strSrc.toStdString().c_str(), &binSrc );

    ret = JS_SSS_splitKey( nN, nK, &binSrc, &pShareList );
    if( ret != 0 ) goto end;

    pCurList = pShareList;

    nCount = JS_BIN_countList( pCurList );

    while( pCurList )
    {
        QString strVal = getHexString( pCurList->Bin.pVal, pCurList->Bin.nLen );
        mShareTable->insertRow(i);

        mShareTable->setRowHeight( i, 10 );
        mShareTable->setItem( i, 0, new QTableWidgetItem( QString( "%1").arg(i)));
        mShareTable->setItem( i, 1, new QTableWidgetItem( strVal ));

        pCurList = pCurList->pNext;
        i++;
    }

end :
    JS_BIN_reset( &binSrc );
    if( pShareList ) JS_BIN_resetList( &pShareList );
}

void SSSDlg::clickJoin()
{
    int ret = 0;
    int nRow = mShareTable->rowCount();
    int nN = mNText->text().toInt();
    int nK = mKText->text().toInt();
    BINList *pShareList = NULL;
    BIN binKey = {0,0};
    char *pKeyVal = NULL;

    if( nRow < 1 ) return;

    mSrcText->clear();

    for( int i = 0; i < nRow; i++ )
    {
        BIN binVal = {0,0};
        QTableWidgetItem *item = mShareTable->item( i, 1 );
        if( item == NULL ) continue;

        QString strVal = item->text();
        JS_BIN_decodeHex( strVal.toStdString().c_str(), &binVal );

        if( pShareList == NULL )
            JS_BIN_createList( &binVal, &pShareList );
        else
            JS_BIN_appendList( pShareList, &binVal );

        JS_BIN_reset( &binVal );
    }

    ret = JS_SSS_joinKey( nK, pShareList, &binKey );
    if( ret != 0 ) goto end;

    if( mSrcTypeCombo->currentText() == "String" )
    {
        JS_BIN_string( &binKey, &pKeyVal );
    }
    else if( mSrcTypeCombo->currentText() == "Hex" )
        JS_BIN_encodeHex( &binKey, &pKeyVal );
    else if( mSrcTypeCombo->currentText() == "Base64" )
        JS_BIN_encodeBase64( &binKey, &pKeyVal );

    mSrcText->setPlainText( pKeyVal );

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
