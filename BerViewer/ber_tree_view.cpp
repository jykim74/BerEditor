#include "ber_item.h"
#include "ber_model.h"
#include "ber_tree_view.h"
#include "mainwindow.h"


#include <QStandardItemModel>
#include <QTreeView>

BerTreeView::BerTreeView( QWidget *parent )
    : QTreeView (parent)
{
    connect( this, SIGNAL(clicked(const QModelIndex&)), this, SLOT(onItemClicked(const QModelIndex&)));
}


void BerTreeView::onItemClicked(const QModelIndex& index )
{
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    BIN& binBer = tree_model->getBer();
    QString strView = GetEditView( &binBer, item );

//    textEdit_->setText( item->text() );
    textEdit_->setText( strView );
}

void BerTreeView::setTextEdit(QTextEdit *txtEdit)
{
    textEdit_ = txtEdit;
}

QString BerTreeView::GetEditView( const BIN *pBer, BerItem *pItem)
{
    QString strView;
    QString strPart;

    strPart = "Class: " + pItem->GetClassString();
    strView += strPart;

    strPart = QString( "  ID: %1").arg(pItem->GetId());
    strView += strPart;

    strPart = QString( "  TAG: %1").arg(pItem->GetTag());
    strView += strPart;

    strPart = QString( "  OFFSET: %1(%2xh)").arg( pItem->GetOffset() ).arg( pItem->GetOffset());
    strView += strPart;

    strPart = QString("  LENGTH: %1(%2xh)").arg(pItem->GetLength()).arg(pItem->GetLength());
    strView += strPart;

    strPart = QString( "  LEVEL: %1" ).arg( pItem->GetLevel() );
    strView += strPart;

    BIN binPart = {0,0};
    QString strVal;

    JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

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

    strView += "--------------------------------------------------------------------------------\r\n";
    strView += GetDataView( &binPart, pItem );

    return strView;
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
            strPart.sprintf( "0x%08X | ", i );
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
