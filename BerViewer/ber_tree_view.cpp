#include "ber_item.h"
#include "ber_model.h"
#include "ber_tree_view.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "ber_item_delegate.h"
#include "edit_value_dlg.h"

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

 //   QFile qss(":/berviewer.qss");
 //   qss.open( QFile::ReadOnly );
 //   setStyleSheet(qss.readAll());

    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(ShowContextMenu(QPoint)));
}


void BerTreeView::onItemClicked(const QModelIndex& index )
{
    QString strInfo;
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    if( item == NULL ) return;

    QTextEdit* rightText = berApplet->mainWindow()->rightText();

    BIN& binBer = tree_model->getBer();
    strInfo = GetInfoView( &binBer, item );
    rightText->setText(strInfo);

    SettingsMgr *set_mgr = berApplet->settingsMgr();

    if( set_mgr->showFullText() )
        GetTableFullView(&binBer, item);
    else
        GetTableView(&binBer, item );

}

void BerTreeView::viewRoot()
{
    QString strInfo;
    BerModel *tree_model = (BerModel *)model();
    BerItem* rootItem = (BerItem *)tree_model->item(0);
    QTextEdit* rightText = berApplet->mainWindow()->rightText();

    BIN& binBer = tree_model->getBer();
    strInfo = GetInfoView( &binBer, rootItem );
    rightText->setText(strInfo);

    SettingsMgr *set_mgr = berApplet->settingsMgr();

    if( set_mgr->showFullText() )
        GetTableFullView(&binBer, rootItem);
    else
        GetTableView(&binBer, rootItem );

    setExpanded( rootIndex(), true );
}



QString BerTreeView::GetInfoView( const BIN *pBer, BerItem *pItem)
{
    QString strView;
    QString strPart;

    int nPos = treePosition();
    QModelIndex index = pItem->index();

    BIN bin = {0,0};
    char *pBitString = NULL;
    JS_BIN_set( &bin, pBer->pVal + pItem->GetOffset(), 1 );
    JS_BIN_bitString( &bin, &pBitString );

    strPart.sprintf( "[T] <b>%s</b> ", pBitString );
    strView += strPart;

    strPart = "Class: <b>" + pItem->GetClassString();
    strPart += "</b>";

    strView += strPart;

    strPart.sprintf( "  ID: <b>%d(0x%X)</b>", pItem->GetId(), pItem->GetId());
    strView += strPart;

    strPart = "  P/C: ";
    if( (pItem->GetId() & JS_FORM_MASK) == JS_CONSTRUCTED )
        strPart += " <b>Constructed</b>";
    else
        strPart += " <b>Primitive</b>";

    strView += strPart;

    strPart.sprintf( "  Tag: <b>%d(0x%X)</b><br>", pItem->GetTag(), pItem->GetTag());
    strView += strPart;

    strPart.sprintf("  Offset: <b>%d(0x%X)</b>", pItem->GetOffset(), pItem->GetOffset());
    strView += strPart;

    strPart.sprintf("  Length: <b>%d(0x%X)</b>", pItem->GetLength(), pItem->GetLength());
    strView += strPart;

    strPart.sprintf( "  Level: <b>%d</b>", pItem->GetLevel() );
    strView += strPart;

//    BIN binPart = {0,0};
//    QString strVal;

//    JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

    QString strPartNL = pItem->GetValueString( pBer );

    if( pItem->GetId() && JS_CONSTRUCTED )
    {
        strView += "<p><p>[";
        strView += pItem->GetTagString();
        strView += "]<p>";
    }
    else {
        strView += "<p><p>[ Value ]<p>";

        for( int i=0; (i*80) < strPartNL.length(); i++ )
        {
            QString strTmp = strPartNL.mid( 80 * i, 80 );
            strView += strTmp;
            strView += "<br>";
        }
    }

//    strView += "--------------------------------------------------------------------------------\r\n";
//    strView += GetDataView( &binPart, pItem );

//    textEdit_->setText(strView);

    if( pBitString ) JS_free( pBitString );
    JS_BIN_reset(&bin);

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

QString BerTreeView::GetTextView()
{
    BerModel *tree_model = (BerModel *)model();
    QModelIndex idx = tree_model->index(0,0);
    BerItem *item = (BerItem *)tree_model->itemFromIndex(idx);

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return "";
    }

    BIN& binBer = tree_model->getBer();

    QString strText = GetInfoView( &binBer, item );
    strText += GetDataView( &binBer, item );

    return strText;
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
    QColor lightGray(Qt::lightGray);

    int len_len = 0;

    JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

    QTableWidget* rightTable = berApplet->mainWindow()->rightTable();

    int row_cnt = rightTable->rowCount();
    for( int k = 0; k < row_cnt; k++ )
        rightTable->removeRow(0);

    for( int i = 0; i < binPart.nLen; i++ )
    {
        if( i % 16 == 0 )
        {
            rightTable->insertRow(line);
            QString address;
            address.sprintf( "0x%08X", i + pItem->GetOffset() );
            rightTable->setItem( line, 0, new QTableWidgetItem( address ));
            rightTable->item( line, 0 )->setBackground( QColor(220,220,250) );
        }

        hex.sprintf( "%02X", binPart.pVal[i] );
        rightTable->setItem( line, (i%16)+1, new QTableWidgetItem(hex));
        rightTable->item( line, (i%16) +1 )->setBackground(lightGray);

        if( i== 0 )
        {
            rightTable->item( line, 1)->setBackground(green);
        }
        else if( i== 1 )
        {
            rightTable->item( line, 2)->setBackground(yellow);

            if( binPart.pVal[i] & JS_LEN_XTND ) len_len = binPart.pVal[i] & JS_LEN_MASK;
        }
        else if( i <= (1 + len_len))
        {
            rightTable->item( line, i + 1 )->setBackground(cyan);
        }


        text += getch( binPart.pVal[i]);

        if( i % 16 - 15 == 0 )
        {
            rightTable->setItem( line, 17, new QTableWidgetItem(text));
            rightTable->item( line, 17 )->setBackground(QColor(210,240,210));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() )
    {
        rightTable->setItem(line, 17, new QTableWidgetItem(text));
        rightTable->item( line, 17 )->setBackground(QColor(210,240,210));
    }

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

    QTableWidget* rightTable = berApplet->mainWindow()->rightTable();

    int row_cnt = rightTable->rowCount();
    for( int k = 0; k < row_cnt; k++ )
        rightTable->removeRow(0);

    for( int i = 0; i < pBer->nLen; i++ )
    {
        int pos = 0;
        if( i % 16 == 0 )
        {
            rightTable->insertRow(line);
            QString address;
            address.sprintf( "0x%08X", i );
            rightTable->setItem( line, 0, new QTableWidgetItem( address ));
            rightTable->item( line, 0 )->setBackground( QColor(220,220,250) );
        }

        hex.sprintf( "%02X", pBer->pVal[i] );
        pos = (i%16) + 1;
        rightTable->setItem( line, pos, new QTableWidgetItem(hex));
        if( i== pItem->GetOffset() )
        {
            rightTable->item( line, pos)->setBackground(green);
            start_row = line;
            start_col = pos;
        }
        else if( i== pItem->GetOffset()+1 )
        {
            rightTable->item( line, pos)->setBackground(yellow);

            if( pBer->pVal[i] & JS_LEN_XTND ) len_len = pBer->pVal[i] & JS_LEN_MASK;
        }
        else if( (i > pItem->GetOffset() + 1 ) && (i <= (pItem->GetOffset() + 1 + len_len)))
        {
            rightTable->item( line, pos )->setBackground(cyan);
        }
        else if( (i > pItem->GetOffset() + 1 ) && ( i < pItem->GetOffset() + pItem->GetHeaderSize() + pItem->GetLength() ))
        {
            rightTable->item(line, pos )->setBackground(lightGray);
        }

        text += getch( pBer->pVal[i]);

        if( i % 16 - 15 == 0 )
        {
            rightTable->setItem( line, 17, new QTableWidgetItem(text));
            rightTable->item( line, 17 )->setBackground(QColor(210,240,210));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() )
    {
        rightTable->setItem(line, 17, new QTableWidgetItem(text));
        rightTable->item( line, 17 )->setBackground(QColor(210,240,210));
    }

    QTableWidgetItem *item = rightTable->item( start_row, start_col );
    rightTable->scrollToItem( item );
}

void BerTreeView::copy()
{
    char *pHex = NULL;
    BerItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binData = {0,0};
    BerModel *tree_model = (BerModel *)model();

    BIN& binBer = tree_model->getBer();
    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    QString strData = GetDataView( &binData, item );

    clipboard->setText(strData);
}

void BerTreeView::treeExpandAll()
{
    expandAll();
}

void BerTreeView::treeExpandNode()
{
    QModelIndex index = currentIndex();
    expand(index);
}

void BerTreeView::treeCollapseAll()
{
    collapseAll();
}

void BerTreeView::treeCollapseNode()
{
    QModelIndex index = currentIndex();
    collapse(index);
}

void BerTreeView::ShowContextMenu(QPoint point)
{
    QMenu menu(this);
    menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
    menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
    menu.addAction(tr("Save node"), this, SLOT(SaveNode()));
    menu.addAction(tr("Save node value"), this, SLOT(SaveNodeValue()));
    menu.addAction(tr("Edit value"), this, SLOT(EditValue()));

    BerItem* item = currentItem();

    if( item->GetTag() == JS_OCTETSTRING || item->GetTag() == JS_BITSTRING )
        menu.addAction( tr("Expand value"), this, SLOT(ExpandValue()));

    menu.exec(QCursor::pos());
}

void BerTreeView::CopyAsHex()
{
    char *pHex = NULL;
    BerItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

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
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

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

    int offset = item->GetOffset();
    if( item->GetTag() == JS_BITSTRING )
    {
        offset += 1; // skip unused bits
    }

    if( item->GetIndefinite() )
    {
        tree_model->parseIndefiniteConstruct( offset + item->GetHeaderSize(), item );
    }
    else
    {
        if( item->GetLength() > 0 )
            tree_model->parseConstruct( offset + item->GetHeaderSize(), item );
    }
}

void BerTreeView::SaveNode()
{
    QFileDialog fileDlg(this, tr("Save as..."));
    fileDlg.setAcceptMode(QFileDialog::AcceptSave);
    fileDlg.setDefaultSuffix("ber");
    if( fileDlg.exec() != QDialog::Accepted )
        return;

    QString fileName = fileDlg.selectedFiles().first();
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
    QFileDialog fileDlg(this, tr("Save as..."));
    fileDlg.setAcceptMode(QFileDialog::AcceptSave);
    fileDlg.setDefaultSuffix("ber");
    if( fileDlg.exec() != QDialog::Accepted )
        return;

    QString fileName = fileDlg.selectedFiles().first();

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    BIN& binBer = tree_model->getBer();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset() + item->GetHeaderSize(), item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toStdString().c_str());
    JS_BIN_reset(&binData);
}

void BerTreeView::EditValue()
{
    int ret = 0;
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);


    EditValueDlg editValueDlg;
    editValueDlg.setItem( item );
    ret = editValueDlg.exec();

//    index = item->index();

    if( ret == QDialog::Accepted )
    {
        tree_model->parseTree();
    }

 //   item->index()
 //   index = currentIndex();
//    onItemClicked( index );
}
