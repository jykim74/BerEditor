#include "ber_item.h"
#include "ber_model.h"
#include "ber_tree_view.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "ber_item_delegate.h"

#include <QStandardItemModel>
#include <QTreeView>
#include <QMenu>
#include <QGuiApplication>
#include <QClipboard>
#include <QFileDialog>

BerTreeView::BerTreeView( QWidget *parent )
    : QTreeView (parent)
{
    connect( this, SIGNAL(clicked(const QModelIndex&)), this, SLOT(onItemClicked(const QModelIndex&)));

    setAcceptDrops(false);
    setContextMenuPolicy(Qt::CustomContextMenu);

    setItemDelegate( new BerItemDelegate(this));

    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(ShowContextMenu(QPoint)));
}


void BerTreeView::onItemClicked(const QModelIndex& index )
{
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    BIN& binBer = tree_model->getBer();
    GetEditView( &binBer, item );

    SettingsMgr *set_mgr = berApplet->settingsMgr();

    if( set_mgr->showFullText() )
        GetTableFullView(&binBer, item);
    else
        GetTableView(&binBer, item );

}

void BerTreeView::viewRoot()
{
    BerModel *tree_model = (BerModel *)model();
    BerItem* rootItem = (BerItem *)tree_model->item(0);

    BIN& binBer = tree_model->getBer();
    GetEditView( &binBer, rootItem );

    SettingsMgr *set_mgr = berApplet->settingsMgr();

    if( set_mgr->showFullText() )
        GetTableFullView(&binBer, rootItem);
    else
        GetTableView(&binBer, rootItem );

    setExpanded( rootIndex(), true );
}

void BerTreeView::setTextEdit(QTextEdit *txtEdit)
{
    textEdit_ = txtEdit;
}

void BerTreeView::setTable(QTableWidget *table)
{
    table_ = table;
}

void BerTreeView::GetEditView( const BIN *pBer, BerItem *pItem)
{
    QString strView;
    QString strPart;

    BIN bin = {0,0};
    char *pBitString = NULL;
    JS_BIN_set( &bin, pBer->pVal + pItem->GetOffset(), 1 );
    JS_BIN_bitString( &bin, &pBitString );

    strPart.sprintf( "[T] %s ", pBitString );
    strView += strPart;

    strPart = "Class: " + pItem->GetClassString();
    strView += strPart;

    strPart.sprintf( "  ID: %d", pItem->GetId());
    strView += strPart;

    if( (pItem->GetId() & FORM_MASK) == CONSTRUCTED )
        strPart = " Construted";
    else
        strPart = " Primitive";

    strView += strPart;

    strPart.sprintf( "  TAG: %d", pItem->GetTag());
    strView += strPart;

    strPart.sprintf("  OFFSET: %d(%xh)", pItem->GetOffset(), pItem->GetOffset());
    strView += strPart;

    strPart.sprintf("  LENGTH: %d(%xh)", pItem->GetLength(), pItem->GetLength());
    strView += strPart;

    strPart.sprintf( "\r\nLEVEL: %d", pItem->GetLevel() );
    strView += strPart;

//    BIN binPart = {0,0};
//    QString strVal;

//    JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

    QString strPartNL = pItem->GetValueString( pBer );

    if( pItem->GetId() && CONSTRUCTED )
    {
        strView += "\r\n[";
        strView += pItem->GetTagString();
        strView += "]\r\n";
    }
    else {
        strView += "\r\n[ VALUE ]\r\n";

        for( int i=0; (i*80) < strPartNL.length(); i++ )
        {
            QString strTmp = strPartNL.mid( 80 * i, 80 );
            strView += strTmp;
            strView += "\r\n";
        }
    }

//    strView += "--------------------------------------------------------------------------------\r\n";
//    strView += GetDataView( &binPart, pItem );

    textEdit_->setText(strView);

    if( pBitString ) JS_free( pBitString );
    JS_BIN_reset(&bin);
}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

QString BerTreeView::GetDataView(const BIN *pData, const BerItem *pItem )
{
    int i;
    QString strView;
    QString strPart;


    for( i = 0; i < pData->nLen; i++ )
    {
        if( i % 16 == 0 )
        {
            strPart.sprintf( "0x%08X | ", i + pItem->offset_ );
            strView += strPart;
        }

        strPart.sprintf( "%02X", pData->pVal[i] );
        strView += strPart;

        if( i % 16 - 15 == 0 )
        {
            int j;
            strView += " | ";

            for( j = i-15; j <= i; j++ )
            {
                strPart.sprintf( "%c", getch(pData->pVal[j]));
                strView += strPart;
            }

            strView += "\r\n";
        }
    }

    if( i % 16 != 0 )
    {
        int j;
        int left = pData->nLen % 16;
        int spaces = 49 - left * 3;

        for( j = 0; j < spaces; j++ )
        {
            strView += " ";
        }

        strView += "| ";

        for( j = i - i % 16; j < pData->nLen; j++ )
        {
            strPart.sprintf( "%c", getch(pData->pVal[j]));
            strView += strPart;
        }
    }

    strView += "\r\n";

    return strView;
}

void BerTreeView::GetTableView(const BIN *pBer, BerItem *pItem)
{
    int line = 0;
    BIN binPart = {0,0};
    QString text;
    QString hex;
    QColor green(Qt::green);
    QColor yellow(Qt::yellow);
    QColor cyan(Qt::cyan);
    int len_len = 0;

    JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

    int row_cnt = table_->rowCount();
    for( int k = 0; k < row_cnt; k++ )
        table_->removeRow(0);

    for( int i = 0; i < binPart.nLen; i++ )
    {
        if( i % 16 == 0 )
        {
            table_->insertRow(line);
            QString address;
            address.sprintf( "0x%08X", i + pItem->GetOffset() );
            table_->setItem( line, 0, new QTableWidgetItem( address ));
        }

        hex.sprintf( "%02X", binPart.pVal[i] );
        table_->setItem( line, (i%16)+1, new QTableWidgetItem(hex));
        if( i== 0 )
        {
            table_->item( line, 1)->setBackgroundColor(green);
        }
        else if( i== 1 )
        {
            table_->item( line, 2)->setBackgroundColor(yellow);

            if( binPart.pVal[i] & LEN_XTND ) len_len = binPart.pVal[i] & LEN_MASK;
        }
        else if( i <= (1 + len_len))
            table_->item( line, i + 1 )->setBackgroundColor(cyan);

        text += getch( binPart.pVal[i]);

        if( i % 16 - 15 == 0 )
        {
            table_->setItem( line, 17, new QTableWidgetItem(text));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() ) table_->setItem(line, 17, new QTableWidgetItem(text));
    JS_BIN_reset(&binPart);
}

void BerTreeView::GetTableFullView(const BIN *pBer, BerItem *pItem)
{
    int line = 0;

    QString text;
    QString hex;
    QColor green(Qt::green);
    QColor yellow(Qt::yellow);
    QColor cyan(Qt::cyan);
    QColor lightGray(Qt::lightGray);

    int len_len = 0;
    int start_col = 0;
    int start_row = 0;

    int row_cnt = table_->rowCount();
    for( int k = 0; k < row_cnt; k++ )
        table_->removeRow(0);

    for( int i = 0; i < pBer->nLen; i++ )
    {
        int pos = 0;
        if( i % 16 == 0 )
        {
            table_->insertRow(line);
            QString address;
            address.sprintf( "0x%08X", i );
            table_->setItem( line, 0, new QTableWidgetItem( address ));
        }

        hex.sprintf( "%02X", pBer->pVal[i] );
        pos = (i%16) + 1;
        table_->setItem( line, pos, new QTableWidgetItem(hex));
        if( i== pItem->GetOffset() )
        {
            table_->item( line, pos)->setBackgroundColor(green);
            start_row = line;
            start_col = pos;
        }
        else if( i== pItem->GetOffset()+1 )
        {
            table_->item( line, pos)->setBackgroundColor(yellow);

            if( pBer->pVal[i] & LEN_XTND ) len_len = pBer->pVal[i] & LEN_MASK;
        }
        else if( (i > pItem->GetOffset() + 1 ) && (i <= (pItem->GetOffset() + 1 + len_len)))
        {
            table_->item( line, pos )->setBackgroundColor(cyan);
        }
        else if( (i > pItem->GetOffset() + 1 ) && ( i < pItem->GetOffset() + pItem->GetHeaderSize() + pItem->GetLength() ))
        {
            table_->item(line, pos )->setBackgroundColor(lightGray);
        }

        text += getch( pBer->pVal[i]);

        if( i % 16 - 15 == 0 )
        {
            table_->setItem( line, 17, new QTableWidgetItem(text));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() ) table_->setItem(line, 17, new QTableWidgetItem(text));
    QTableWidgetItem *item = table_->item( start_row, start_col );
    table_->scrollToItem( item );
}

void BerTreeView::ShowContextMenu(QPoint point)
{
    BerModel *tree_model = (BerModel *)model();


    QMenu menu(this);
    menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
    menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
    menu.addAction(tr("Save node"), this, SLOT(SaveNode()));
    menu.addAction(tr("Save node value"), this, SLOT(SaveNodeValue()));

    BerItem* item = currentItem();

    if( item->GetTag() == OCTETSTRING || item->GetTag() == BITSTRING )
        menu.addAction( tr("Expand value"), this, SLOT(ExpandValue()));

    menu.exec(QCursor::pos());
}

void BerTreeView::CopyAsHex()
{
    char *pHex = NULL;
    BerItem* item = currentItem();
    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binData = {0,0};
    BerModel *tree_model = (BerModel *)model();

    BIN& binBer = tree_model->getBer();
    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    JS_BIN_encodeHex( &binData, &pHex );
    clipboard->setText(pHex);
    if( pHex ) JS_free(pHex);
    JS_BIN_reset(&binData);
}

void BerTreeView::CopyAsBase64()
{
    char *pBase64 = NULL;
    BerItem* item = currentItem();
    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binData = {0,0};
    BerModel *tree_model = (BerModel *)model();

    BIN& binBer = tree_model->getBer();
    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    JS_BIN_encodeBase64( &binData, &pBase64 );
    clipboard->setText(pBase64);
    if( pBase64 ) JS_free(pBase64);
    JS_BIN_reset(&binData);
}

BerItem* BerTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    return item;
}

void BerTreeView::ExpandValue()
{
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    if( item->GetIndefinite() )
        tree_model->parseIndefiniteConstruct( item->GetOffset() + item->GetHeaderSize(), item );
    else
        tree_model->parseConstruct( item->GetOffset() + item->GetHeaderSize(), item );
}

void BerTreeView::SaveNode()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;BER Files (*.ber)"),
                                                     &selectedFilter,
                                                     options );

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    BIN& binBer = tree_model->getBer();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toStdString().c_str());
    JS_BIN_reset( &binData );
}

void BerTreeView::SaveNodeValue()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;BER Files (*.ber)"),
                                                     &selectedFilter,
                                                     options );

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    BIN& binBer = tree_model->getBer();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset() + item->GetHeaderSize(), item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toStdString().c_str());
    JS_BIN_reset(&binData);
}
