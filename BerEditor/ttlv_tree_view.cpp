#include <QMenu>
#include <QGuiApplication>
#include <QClipboard>

#include "ttlv_tree_view.h"
#include "edit_ttlv_dlg.h"
#include "ttlv_tree_item.h"
#include "ttlv_tree_model.h"

#include <QStandardItemModel>
#include <QTreeView>
#include <QTableWidget>
#include <QFileDialog>

#include "js_bin.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "make_ttlv_dlg.h"

TTLVTreeView::TTLVTreeView( QWidget *parent )
    : QTreeView(parent)
{
    connect( this, SIGNAL(clicked(const QModelIndex&)), this, SLOT(onItemClicked(const QModelIndex&)));
    setContextMenuPolicy(Qt::CustomContextMenu);

    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(leftContextMenu(QPoint)));

    QFile qss(":/ttlvreader.qss");
    qss.open( QFile::ReadOnly );
    setStyleSheet(qss.readAll());
    qss.close();

    static QFont font;
    QString strFont = berApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    setFont(font);
}

TTLVTreeItem* TTLVTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    TTLVTreeItem *item = (TTLVTreeItem *)tree_model->itemFromIndex(index);

    return item;
}

TTLVTreeItem* TTLVTreeView::getNext( TTLVTreeItem *pItem )
{
    const TTLVTreeItem *pParentItem = nullptr;
    const TTLVTreeItem *pCurItem = nullptr;
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();

    QModelIndex idx;
    int nCurRow = 0;

    if( pItem == NULL )
        return (TTLVTreeItem *)tree_model->item(0,0);

    pCurItem = pItem;
    if( pCurItem->hasChildren() == true )
    {
        return (TTLVTreeItem *)pCurItem->child(0);
    }

    nCurRow = pCurItem->row();
#if 0
    QModelIndex newIdx = indexBelow( pCurItem->index() );
    if( newIdx.isValid() ) return (TTLVTreeItem *)tree_model->itemFromIndex( newIdx );
#else
    pParentItem = (TTLVTreeItem *)pCurItem->parent();
    if( pParentItem == NULL ) return nullptr;

    if( pParentItem->rowCount() > (nCurRow + 1) )
        return (TTLVTreeItem *)pParentItem->child( nCurRow + 1 );

    nCurRow = pParentItem->row();
    pCurItem = pParentItem;
#endif

    while( pCurItem )
    {
        pParentItem = (TTLVTreeItem *)pCurItem->parent();
        if( pParentItem == nullptr ) return nullptr;

        if( pParentItem->rowCount() > (nCurRow + 1 ) )
            return (TTLVTreeItem *)pParentItem->child( nCurRow + 1 );

        nCurRow = pParentItem->row();
        pCurItem = pParentItem;
    }

    return nullptr;
}

TTLVTreeItem* TTLVTreeView::getPrev( TTLVTreeItem *pItem )
{
    TTLVTreeItem *pChildItem = nullptr;
    TTLVTreeItem *pCurItem = nullptr;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();

    QModelIndex idx;
    int nCurRow = 0;

    if( pItem == NULL )
        return (TTLVTreeItem *)tree_model->item(0,0);

    pCurItem = pItem;

#if 0
    QModelIndex newIdx = indexAbove( pCurItem->index() );
    if( newIdx.row() < 0 )
    {
        return (TTLVTreeItem *)pCurItem->parent();
    }

    pCurItem = (TTLVTreeItem *)tree_model->itemFromIndex( newIdx );
#else
    TTLVTreeItem *pParent = (TTLVTreeItem *)pCurItem->parent();
    if( pParent == NULL ) return nullptr;

    nCurRow = pCurItem->row();
    if( nCurRow <= 0 ) return pParent;

    pCurItem = (TTLVTreeItem *)pParent->child( nCurRow - 1 );
#endif

    while( pCurItem )
    {
        if( pCurItem->hasChildren() == false ) return pCurItem;

        nCurRow = pCurItem->rowCount();
        pChildItem = (TTLVTreeItem *)pCurItem->child( nCurRow - 1 );

        pCurItem = pChildItem;
    }

    return nullptr;
}

void TTLVTreeView::viewRoot()
{
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    QModelIndex ri = tree_model->index(0,0);
    onItemClicked( ri );
    setExpanded( rootIndex(), true );
    expand(ri);
}

void TTLVTreeView::viewCurrent()
{
    QModelIndex ci = currentIndex();

    if( ci.isValid() == true )
    {
        onItemClicked( ci );
        setExpanded( ci, true );
    }
    else {
        viewRoot();
    }
}

void TTLVTreeView::expandToTop( const TTLVTreeItem *pItem )
{
    TTLVTreeItem *pParent = nullptr;
    if( pItem == NULL ) return;

    expand( pItem->index() );
    pParent = (TTLVTreeItem *)pItem->parent();

    while( pParent )
    {
        expand( pParent->index() );
        pParent = (TTLVTreeItem *)pParent->parent();
    }
}




void TTLVTreeView::onItemClicked( const QModelIndex& index )
{
    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    TTLVTreeItem *item = (TTLVTreeItem *)left_model->itemFromIndex(index);

    SettingsMgr *setMgr = berApplet->settingsMgr();
    int nWidth = setMgr->getHexAreaWidth();

    viewTable( item, setMgr->getShowTTLVSelOnly() );

    getInfoView( item, nWidth );
}

void TTLVTreeView::leftContextMenu( QPoint point )
{
    QMenu menu(this);
    TTLVTreeItem* item = currentItem();

    if( item != NULL )
    {
        menu.addAction(tr("Copy Information"), this, SLOT(copy()));
        menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
        menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
        menu.addAction( tr("Save node"), this, &TTLVTreeView::saveNode );
        menu.addAction( tr("Save node value"), this, &TTLVTreeView::saveNodeValue );

        if( item->isStructure() == true )
        {
            menu.addAction( tr( "Insert node" ), this, &TTLVTreeView::insertNode );
        }
        else
        {
            menu.addAction( tr("Edit node"), this, &TTLVTreeView::editNode );
        }

        if( item->parent() )
            menu.addAction( tr( "Delete node" ), this, &TTLVTreeView::deleteNode );
    }

    menu.exec(QCursor::pos());
}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

void TTLVTreeView::viewTable( TTLVTreeItem *pItem, bool bPart )
{
    str_edit_.clear();
    int table_idx = berApplet->mainWindow()->tableCurrentIndex();

    if( table_idx == TABLE_IDX_XML )
        viewXML( pItem, bPart );
    else if( table_idx == TABLE_IDX_TXT )
        viewText( pItem, bPart );
    else if( table_idx == TABLE_IDX_JSON )
        viewJSON( pItem, bPart );
    else
        viewHex( pItem, bPart );
}

void TTLVTreeView::viewXML( TTLVTreeItem *pItem, bool bPart )
{
    CodeEditor *xmlEdit = berApplet->mainWindow()->rightXML();
    xmlEdit->clear();

    QTextCursor xml_cursor = xmlEdit->textCursor();
    QTextCharFormat format = xmlEdit->currentCharFormat();
    //format.setFontWeight(QFont::Normal);
    format.setForeground(Qt::black);
    xml_cursor.setCharFormat( format );
    xmlEdit->setTextCursor(xml_cursor);

    addEdit( 0, "<!-- XML Decoded Message -->\n" );

    if( bPart == false )
    {
        TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
        TTLVTreeItem *root = (TTLVTreeItem *)tree_model->item(0,0);

        setItemXML( 0, root, pItem );
        xmlEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            xml_cursor.setPosition( pos_start_ );
            xml_cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );

            QTextCharFormat format = xmlEdit->currentCharFormat();
        //            format.setFontWeight(QFont::Bold);
            format.setForeground(Qt::blue);
            xml_cursor.setCharFormat( format );
            xml_cursor.clearSelection();
            xml_cursor.setPosition( pos_start_ + 512 );
            xmlEdit->setTextCursor(xml_cursor);
        }
    }
    else
    {
        setItemXML( 0, pItem );
        xmlEdit->setPlainText( str_edit_ );
        xmlEdit->moveCursor(QTextCursor::Start);
    }

    xmlEdit->update();
}

void TTLVTreeView::viewText( TTLVTreeItem *pItem, bool bPart )
{
    CodeEditor *txtEdit = berApplet->mainWindow()->rightText();
    txtEdit->clear();

    QTextCursor cursor = txtEdit->textCursor();
    QTextCharFormat format = txtEdit->currentCharFormat();
    //format.setFontWeight(QFont::Normal);
    format.setForeground(Qt::black);
    cursor.setCharFormat( format );
    txtEdit->setTextCursor(cursor);

    addEdit( 0, "-- Text Decoded Message --\n" );

    if( bPart == false )
    {
        TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
        TTLVTreeItem *root = (TTLVTreeItem *)tree_model->item(0,0);

        setItemText( 0, root, pItem );
        txtEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            cursor.setPosition( pos_start_ );
            cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );

            QTextCharFormat format = txtEdit->currentCharFormat();
            // format.setFontWeight(QFont::Bold);
            format.setForeground(Qt::blue);
            cursor.setCharFormat( format );
            cursor.clearSelection();
            cursor.setPosition( pos_start_ + 512 );
            txtEdit->setTextCursor(cursor);
        }
    }
    else
    {
        setItemText( 0, pItem );
        txtEdit->setPlainText( str_edit_ );
        txtEdit->moveCursor(QTextCursor::Start);
    }

    txtEdit->update();
}

void TTLVTreeView::viewJSON( TTLVTreeItem *pItem, bool bPart )
{
    CodeEditor *txtEdit = berApplet->mainWindow()->rightJSON();
    txtEdit->clear();

    QTextCursor cursor = txtEdit->textCursor();
    QTextCharFormat format = txtEdit->currentCharFormat();
    //format.setFontWeight(QFont::Normal);
    format.setForeground(Qt::black);
    cursor.setCharFormat( format );
    txtEdit->setTextCursor(cursor);

    if( bPart == false )
    {
        TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
        TTLVTreeItem *root = (TTLVTreeItem *)tree_model->item(0,0);

        addEdit( 0, "[\n" );
        setItemJSON( 1, root, false, pItem );
        addEdit( 0, "]\n" );

        txtEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            cursor.setPosition( pos_start_ );
            cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );

            QTextCharFormat format = txtEdit->currentCharFormat();
            // format.setFontWeight(QFont::Bold);
            format.setForeground(Qt::blue);
            cursor.setCharFormat( format );
            cursor.clearSelection();
            cursor.setPosition( pos_start_ + 512 );
            txtEdit->setTextCursor(cursor);
        }
    }
    else
    {
        addEdit( 0, "[\n" );
        setItemJSON( 1, pItem, false );
        addEdit( 0, "]\n" );
        txtEdit->setPlainText( str_edit_ );

        txtEdit->moveCursor(QTextCursor::Start);
    }

    txtEdit->update();
}

void TTLVTreeView::viewHex( TTLVTreeItem *pItem, bool bPart )
{
    int line = 0;
    int start_col = 0;
    int start_row = 0;

    QString text;
    QString hex;
    QColor green(Qt::green);
    QColor yellow(Qt::yellow);
    QColor cyan(Qt::cyan);
    QColor lightGray(Qt::lightGray);

    QTableWidget* rightTable = berApplet->mainWindow()->rightTable();

    int nStart = 0;
    int nEnd = 0;
    int nMod = 0;

    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    BIN TTLV = left_model->getTTLV();

    if( bPart == false )
    {
        nStart = 0;
        nEnd = TTLV.nLen;
        nMod = 0;
    }
    else
    {
        nStart = pItem->getOffset();
        nEnd = nStart + pItem->getLengthTTLV();
        nMod = nStart % 16;
    }

    rightTable->setRowCount(0);

    for( int i = nStart; i < nEnd; i++ )
    {
        int pos = 0;
        int len = 0;
        int pad = 0;

        if( ((i-nMod) % 16) == 0 )
        {
            rightTable->insertRow(line);
            rightTable->setRowHeight( line, 10 );

            QString address;
            address = QString( "%1" ).arg( i, 8, 16, QLatin1Char( '0' ));
            QTableWidgetItem *addrItem = new QTableWidgetItem( address );
            addrItem->setFlags(addrItem->flags() & ~Qt::ItemIsSelectable );
            rightTable->setItem( line, 0, addrItem);
            rightTable->item( line, 0 )->setBackgroundColor( QColor(220,220,250) );
        }

        hex = QString( "%1" ).arg( TTLV.pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
        pos = ((i-nMod)%16) + 1;
        rightTable->setItem( line, pos, new QTableWidgetItem(hex));

        len = pItem->getLengthInt();
        pad = 8 - (len % 8);
        if( pad == 8 ) pad = 0;

        if( i >= pItem->getOffset() && i < pItem->getOffset() + 3 )
        {
            if( i == pItem->getOffset() )
            {
                start_row = line;
                start_col = pos;
            }
            rightTable->item( line, pos )->setBackgroundColor(green);
        }
        else if( i == pItem->getOffset() + 3 )
        {
            rightTable->item( line, pos )->setBackgroundColor(yellow);
        }
        else if( i >= pItem->getOffset() + 4 && i < pItem->getOffset() + 8 )
        {
            rightTable->item( line, pos )->setBackgroundColor(cyan);
        }
        else if( i >= pItem->getOffset() + 8 && i < pItem->getOffset() + 8 + len )
        {
            rightTable->item( line, pos )->setBackgroundColor(kValueColor);
        }
        else if( i >= (pItem->getOffset() + 8 + len) && i < (pItem->getOffset() + 8 + len + pad ))
        {
            rightTable->item( line, pos )->setBackgroundColor(lightGray);
        }


        text += getch( TTLV.pVal[i] );

        if( (i-nMod) % 16 - 15 == 0 )
        {
            QTableWidgetItem *textItem = new QTableWidgetItem( text );
            textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
            rightTable->setItem( line, 17, textItem );
            rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() )
    {
        QTableWidgetItem *textItem = new QTableWidgetItem( text );
        textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
        rightTable->setItem( line, 17, textItem);
        rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
    }

    QTableWidgetItem *item = rightTable->item( start_row, start_col );
    rightTable->scrollToItem( item, ScrollHint::PositionAtCenter );
}

void TTLVTreeView::getInfoView(TTLVTreeItem *pItem, int nWidth )
{
    int nFieldWidth = -16;
    BIN binTTLV = berApplet->getTTLV();
    BIN binHeader = {0,0};
    int nType = -1;
    QString strVal;
    BIN binVal = {0,0};

    pItem->getHeader( &binHeader );

    berApplet->mainWindow()->infoClear();

    berApplet->line();
    berApplet->info( QString( "== TTLV Information [Depth:%1]\n").arg(pItem->getLevel()) );
    berApplet->line();

    berApplet->info( QString( "Header   : %1\n" ).arg( getHexString( &binHeader )));
    berApplet->info( QString( "Tag      : 0x%1 - %2\n" ).arg( pItem->getTagHex(), nFieldWidth ).arg( pItem->getTagName() ));
    berApplet->info( QString( "Type     : 0x%1 - %2\n").arg( pItem->getTypeHex(), nFieldWidth ).arg( pItem->getTypeName() ));
    berApplet->info( QString( "Length   : 0x%1 - %2 Bytes\n" ).arg( pItem->getLengthHex(), nFieldWidth ).arg( pItem->getLengthInt() ));
    berApplet->info( QString( "Offset   : 0x%1 - %2\n").arg( pItem->getOffset(), nFieldWidth, 16).arg( pItem->getOffset()) );

    strVal = pItem->getPrintValue( &binTTLV, &nType, nWidth );

    if( nType == KMIP_TYPE_INTEGER || nType == KMIP_TYPE_TEXT_STRING || nType == KMIP_TYPE_ENUMERATION )
    {
        pItem->getValue( &binTTLV, &binVal );

        berApplet->line();
        berApplet->info( "-- Print Value\n" );
        berApplet->line2();
        berApplet->info( strVal );
        berApplet->info( "\n" );

        berApplet->line();
        berApplet->info( "-- Hex Value\n" );
        berApplet->line2();
        berApplet->info( getHexStringArea( &binVal, nWidth));
    }
    else
    {
        berApplet->line();
        berApplet->info( "-- Hex Value\n" );
        berApplet->line2();
        berApplet->info( QString( "%1").arg( strVal ) );
    }

    berApplet->info( "\n" );
    berApplet->line();

    berApplet->mainWindow()->infoText()->moveCursor(QTextCursor::Start);
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binVal );
}

QString TTLVTreeView::GetTextView()
{
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    TTLVTreeItem *item = currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There are no items selected."), this );
        return "";
    }


    BIN binBer = tree_model->getTTLV();
    BIN binData = {0,0};

    JS_BIN_set( &binData, &binBer.pVal[item->getOffset()], item->getLengthInt() + 8 );
    QString strText = berApplet->mainWindow()->getInfo();
    strText += "\n=================================================================================\n";
    strText += getHexView( "All Data", &binData );
    JS_BIN_reset( &binData );

    return strText;
}

void TTLVTreeView::CopyAsHex()
{
    char *pHex = NULL;
    BIN binVal = {0,0};

    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binTTLV = berApplet->getTTLV();

    JS_BIN_set( &binVal, binTTLV.pVal + item->getOffset(), item->getLengthTTLV() );
    JS_BIN_encodeHex( &binVal, &pHex );
    clipboard->setText(pHex);
    if( pHex ) JS_free(pHex);
    JS_BIN_reset( &binVal );
}

void TTLVTreeView::CopyAsBase64()
{
    char *pBase64 = NULL;
    BIN binVal = {0,0};
    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    BIN binTTLV = berApplet->getTTLV();
    QClipboard *clipboard = QGuiApplication::clipboard();

    JS_BIN_set( &binVal, binTTLV.pVal + item->getOffset(), item->getLengthTTLV() );
    JS_BIN_encodeBase64( &binVal, &pBase64 );
    clipboard->setText(pBase64);
    if( pBase64 ) JS_free(pBase64);
    JS_BIN_reset( &binVal );
}

void TTLVTreeView::copy()
{
    TTLVTreeItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no selected item"), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();

    QString strLog = berApplet->mainWindow()->getInfo();
    clipboard->setText(strLog);
}

void TTLVTreeView::treeExpandAll()
{
    expandAll();
}

void TTLVTreeView::treeExpandNode()
{
    QModelIndex index = currentIndex();
    expand(index);
}

void TTLVTreeView::treeCollapseAll()
{
    collapseAll();
}

void TTLVTreeView::treeCollapseNode()
{
    QModelIndex index = currentIndex();
    collapse(index);
}

void TTLVTreeView::insertNode()
{
    int ret = 0;
    BIN binData = {0,0};


    TTLVTreeModel *ttlv_model = (TTLVTreeModel *)model();
    TTLVTreeItem* item = currentItem();

    if( item->isStructure() == false )
    {
        berApplet->warningBox( tr( "The item is not structured" ), this );
        return;
    }

    MakeTTLVDlg makeTTLV;
    makeTTLV.setHeadLabel( tr( "Insert TTLV [ Tag Type Length Value ]" ) );
    ret = makeTTLV.exec();

    if( ret == QDialog::Accepted )
    {
        bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), this, false );
        if( bVal == false ) return;

        QString strData = makeTTLV.getData();
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        bool bFirst = makeTTLV.mFirstSetCheck->isChecked();
        const TTLVTreeItem *pAddItem = (const TTLVTreeItem *)ttlv_model->addItem( item, bFirst, &binData );

        JS_BIN_reset( &binData );

        if( pAddItem )
        {
            int nOffset = pAddItem->offset_;
            berApplet->mainWindow()->reloadTTLV();
            const TTLVTreeItem *findItem = ttlv_model->findItemByOffset( nullptr, nOffset );
            if( findItem )
            {
                QModelIndex idx = findItem->index();
                expandToTop( findItem );
                clicked( idx );
                setCurrentIndex( idx );
            }
        }
        else
        {
            berApplet->warningBox( tr( "failed to insert" ), this );
        }
    }
}

void TTLVTreeView::editNode()
{
    int ret = 0;

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    BIN binTTLV = berApplet->getTTLV();

    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), this );
        return;
    }

    EditTTLVDlg editTTLV;
    editTTLV.setHeadLabel( tr( "Edit TTLV [ Tag Type Length Value ]" ) );
    ret = editTTLV.exec();
}

void TTLVTreeView::deleteNode()
{
    int ret = 0;

    TTLVTreeItem *pItem = berApplet->mainWindow()->ttlvTree()->currentItem();
    BIN binTTLV = berApplet->getTTLV();
    TTLVTreeModel *ttlv_model = (TTLVTreeModel *)model();
    const TTLVTreeItem *pParent = NULL;

    if( pItem == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), this );
        return;
    }

    if( pItem->parent() == nullptr )
    {
        berApplet->warningBox( tr( "Top-level items cannot be deleted" ), this );
        return;
    }

    pParent = (TTLVTreeItem *)pItem->parent();

    bool bVal = berApplet->yesOrCancelBox( tr("Are you sure you want to delete it?"), this, true );
    if( bVal == false ) return;

    ret = ttlv_model->removeItem( pItem );
    if( ret == JSR_OK )
    {
        int nOffset = pParent->offset_;
        berApplet->mainWindow()->reloadTTLV();

        const TTLVTreeItem *findItem = ttlv_model->findItemByOffset( nullptr, nOffset );
        if( findItem )
        {
            QModelIndex idx = findItem->index();
            expandToTop( findItem );
            clicked( idx );
            setCurrentIndex( idx );
        }
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete: %1").arg( JERR(ret)), this );
    }
}

const QString TTLVTreeView::saveNode()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( this, JS_FILE_TYPE_BIN, strPath );
    if( fileName.length() < 1 ) return "";

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return "";

    BIN binData = {0,0};
    BIN binTTLV = berApplet->getTTLV();

    pItem->getDataAll( &binTTLV, &binData );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binData );

    return fileName;
}

void TTLVTreeView::saveNodeValue()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( this, JS_FILE_TYPE_BIN, strPath );
    if( fileName.length() < 1 ) return;

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return;

    BIN binData = {0,0};
    BIN binTTLV = berApplet->getTTLV();

    pItem->getValueWithPad( &binTTLV, &binData );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binData );
}


void TTLVTreeView::setItemText( int level, TTLVTreeItem* item, TTLVTreeItem *setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    BIN binTTLV = tree_model->getTTLV();
    QString strName = item->getTagName().toUpper();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isStructure() )
    {
        addEdit( level, QString("%1 {\n").arg( strName ) );

        while( 1 )
        {
            TTLVTreeItem* child = (TTLVTreeItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemText( level + 1, child, setItem );
        }

        addEdit( level, "}\n" );
    }
    else
    {
        QString strValue = item->getPrintValue( &binTTLV );

        addEdit( level, QString( "%1" ).arg( strName ) );
        addEdit( 0, QString( " = %1\n" ).arg( strValue ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

void TTLVTreeView::setItemXML( int level, TTLVTreeItem* item, TTLVTreeItem *setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    BIN binTTLV = tree_model->getTTLV();


    QString strName = item->getTagName().toUpper();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isStructure() )
    {
        addEdit( level, QString("<%1>\n").arg( strName) );

        while( 1 )
        {
            TTLVTreeItem* child = (TTLVTreeItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemXML( level+1, child, setItem );
        }

        addEdit( level, QString("</%1>\n").arg( strName ) );
    }
    else
    {
        QString strValue = item->getPrintValue( &binTTLV );

        addEdit( level, QString( "<%1>" ).arg( strName ) );
        addEdit( 0, QString( "%1" ).arg( strValue ) );
        addEdit( 0, QString( "</%1>\n" ).arg( strName ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

void TTLVTreeView::setItemJSON( int level, TTLVTreeItem* item, bool bNext, TTLVTreeItem *setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    BIN binTTLV = tree_model->getTTLV();


    QString strName = item->getTagName().toUpper();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isStructure() )
    {
        addEdit( level, QString("\"%1\": {\n" ).arg( strName) );

        while( 1 )
        {
            bool bNext = false;
            TTLVTreeItem* child = (TTLVTreeItem *)item->child( pos );
            if( child == NULL ) break;

            pos++;
            BerItem* next = (BerItem *)item->child( pos );
            if( next ) bNext = true;

            setItemJSON( level+1, child, bNext, setItem );
        }

        addEdit( level, QString( "}" ) );
        if( bNext == true ) addEdit( 0, "," );
        addEdit( 0, QString( "\n" ));
    }
    else
    {
        QString strValue = item->getPrintValue( &binTTLV );

        addEdit( level, QString( "\"%1\": " ).arg( strName ) );
        addEdit( 0, QString( "\"%1\"" ).arg( strValue ) );

        if( bNext == true ) addEdit( 0, "," );
        addEdit( 0, QString( "\n" ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

void TTLVTreeView::addEdit( int level, const QString& strMsg )
{
    if( level > 0 )
    {
        QString strEmpty = QString( "%1" ).arg( " ", 4 * level, QLatin1Char( ' ' ));
        str_edit_ += strEmpty;
    }

    str_edit_ += strMsg;
}
