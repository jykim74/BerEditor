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

    strPart = "Class: " + pItem->GetClassString();
    strView += strPart;

    strPart.sprintf( "  ID: %d", pItem->GetId());
    strView += strPart;

    strPart.sprintf( "  TAG: %d", pItem->GetTag());
    strView += strPart;

    strPart.sprintf("  OFFSET: %d(%xh)", pItem->GetOffset(), pItem->GetOffset());
    strView += strPart;

    strPart.sprintf("  LENGTH: %d(%xh)", pItem->GetLength(), pItem->GetLength());
    strView += strPart;

    strPart.sprintf( "  LEVEL: %d", pItem->GetLevel() );
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
    menu.addAction("Copy as hex", this, SLOT(CopyAsHex()));
    menu.addAction("Copy as base64", this, SLOT(CopyAsBase64()));

    menu.exec(QCursor::pos());
}

void BerTreeView::CopyAsHex()
{

}

void BerTreeView::CopyAsBase64()
{

}
