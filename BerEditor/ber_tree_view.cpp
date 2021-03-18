#include "ber_item.h"
#include "ber_model.h"
#include "ber_tree_view.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "ber_item_delegate.h"
#include "edit_value_dlg.h"
#include "insert_ber_dlg.h"
#include "common.h"

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
    QString strInfo;
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    if( item == NULL ) return;

    BIN& binBer = tree_model->getBer();

    SettingsMgr *set_mgr = berApplet->settingsMgr();

    if( set_mgr->showPartOnly() )
        GetTableView(&binBer, item );
    else
        GetTableFullView(&binBer, item);

    logItem( item );
}

void BerTreeView::viewRoot()
{
    BerModel *tree_model = (BerModel *)model();
    QModelIndex ri = tree_model->index(0,0);
    onItemClicked( ri );
    setExpanded( rootIndex(), true );
}

void BerTreeView::logItem( BerItem *pItem )
{
    BerModel *tree_model = (BerModel *)model();
    BIN& binBer = tree_model->getBer();

    BIN bin = {0,0};
    BIN header = {0,0};

    char *pBitString = NULL;
    JS_BIN_set( &bin, binBer.pVal + pItem->GetOffset(), 1 );
    JS_BIN_bitString( &bin, &pBitString );
    unsigned char cID = pItem->GetId();
    unsigned char cLen = 0x00;
    int nLenSize = 0;
    unsigned char sLen[4];

    pItem->getHeaderBin( &header );
    if( header.nLen < 2 ) return;

    cLen = header.pVal[1];
    if( cLen & JS_LEN_XTND )
    {
        nLenSize = cLen & JS_LEN_MASK;
        memcpy( sLen, &header.pVal[2], nLenSize );
    }
    else
    {
        nLenSize = 1;
        sLen[0] = cLen;
    }

    QString strPC;
    if( pItem->GetId() & JS_CONSTRUCTED )
        strPC = "Constructed";
    else
        strPC = "Primitive";

    QString strOffset;
    strOffset.sprintf( "0x%08X", pItem->GetOffset() );

    berApplet->mainWindow()->logText()->clear();
    berApplet->log( "====================================================================================\n" );
    berApplet->log( QString( "== BER Information [Depth:%1]\n" ).arg(pItem->GetLevel()) );
    berApplet->log( "====================================================================================\n" );
    berApplet->log( QString( "Header      : %1\n").arg( getHexString(header.pVal, header.nLen)));
    berApplet->log( QString( "[T]         : %1 - %2\n" ).arg(getHexString(bin.pVal,1)).arg(pBitString) );
    berApplet->log( QString( "Class       : %1\n").arg( pItem->GetClassString()));
    berApplet->log( QString( "ID          : %1 - %2\n").arg( getHexString( &cID, 1) ).arg( cID ));
    berApplet->log( QString( "P/C         : %1\n").arg(strPC));
    berApplet->log( QString( "Tag         : %1 - %2\n").arg( pItem->GetTag(), 2, 16, QChar('0')).arg(pItem->GetTagString()));
    berApplet->log( QString( "Offset      : %1 - %2\n" ).arg( strOffset ).arg(pItem->GetOffset()));
    berApplet->log( QString( "Length      : %1 - %2 Bytes\n" ).arg( getHexString(sLen, nLenSize) ).arg(pItem->GetLength()));
    berApplet->log( "====================================================================================\n" );

    QString strVal = pItem->GetValueString( &binBer );
    berApplet->log( strVal );

    berApplet->mainWindow()->logText()->moveCursor(QTextCursor::Start);
    if( pBitString ) JS_free( pBitString );
    JS_BIN_reset( &bin );
    JS_BIN_reset( &header );
}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

QString BerTreeView::GetTextView()
{
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return "";
    }


    BIN& binBer = tree_model->getBer();
    BIN binData = {0,0};

    JS_BIN_set( &binData, &binBer.pVal[item->GetOffset()], item->GetHeaderSize() + item->GetLength() );
    QString strText = berApplet->mainWindow()->getLog();
    strText += "\n====================================================================================\n";
    strText += getHexView( "All Data", &binData );
    JS_BIN_reset( &binData );

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
    BerItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();

    QString strLog = berApplet->mainWindow()->getLog();
    clipboard->setText(strLog);
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

void BerTreeView::treeExpandItem( int nRow, int nCol )
{

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

    if( item->isConstructed() )
        menu.addAction( tr( "Insert BER" ), this, SLOT(InsertBER()));

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

    if( ret == QDialog::Accepted )
    {
        tree_model->parseTree();
        QModelIndex ri = tree_model->index(0,0);
        expand(ri);
    }
}

void BerTreeView::InsertBER()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binHeader = {0,0};

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    if( item->isConstructed() == false ) return;

    BIN& binBer = tree_model->getBer();

    InsertBerDlg insertBerDlg;

    ret = insertBerDlg.exec();

    if( ret == QDialog::Accepted )
    {
        int nOrgLen = 0;
        int nOrgHeaderLen = 0;
        int nDiffLen = 0;

        QModelIndexList indexList;
        QString strData = insertBerDlg.getData();

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        nOrgLen = item->GetLength();
        nOrgHeaderLen = item->GetHeaderSize();

        JS_BIN_insertBin( item->GetOffset() + nOrgHeaderLen + nOrgLen, &binData, &binBer );

        item->changeLength( nOrgLen + binData.nLen, &nDiffLen );
        if( nDiffLen == 0 ) goto end;

        item->getHeaderBin( &binHeader );
        JS_BIN_changeBin( item->GetOffset(), nOrgHeaderLen, &binHeader, &binBer );
        tree_model->resizeParentHeader( nDiffLen, item, indexList );

        tree_model->parseTree();       
        QModelIndex ri = tree_model->index(0,0);
        expand(ri);
    }

end:
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binHeader );
}
