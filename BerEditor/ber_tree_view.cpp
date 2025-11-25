/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "ber_item.h"
#include "ber_model.h"
#include "ber_tree_view.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "ber_item_delegate.h"
#include "edit_value_dlg.h"
#include "make_ber_dlg.h"
#include "common.h"
#include "js_pki_tools.h"

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

    QFile qss(":/bereditor.qss");
    qss.open( QFile::ReadOnly );
    setStyleSheet(qss.readAll());
    qss.close();

    static QFont font;
    QString strFont = berApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    setFont(font);
}


void BerTreeView::onItemClicked(const QModelIndex& index )
{
    QString strInfo;
    BerModel *tree_model = (BerModel *)model();
    BerItem *item = NULL;

    item = (BerItem *)tree_model->itemFromIndex(index);
    if( item == NULL ) return;

    const BIN& binBer = tree_model->getBER();

    SettingsMgr *set_mgr = berApplet->settingsMgr();
    int nWidth = set_mgr->getHexAreaWidth();

    if( set_mgr->showPartOnly() )
    {
        GetTableView(&binBer, item );
    }
    else
    {
        GetTableFullView(&binBer, item);
    }

    infoItem( item, nWidth );
}

void BerTreeView::viewRoot()
{
    BerModel *tree_model = (BerModel *)model();
    QModelIndex ri = tree_model->index(0,0);
    onItemClicked( ri );
    setExpanded( rootIndex(), true );
    expand( ri );
}

void BerTreeView::viewCurrent()
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

void BerTreeView::infoItem( BerItem *pItem, int nWidth )
{
    int nFieldWidth = -20;
    BerModel *tree_model = (BerModel *)model();
    const BIN& binBer = tree_model->getBER();

    BIN bin = {0,0};
    BIN header = {0,0};
    BIN binVal = {0,0};

    char *pBitString = NULL;
    JS_BIN_set( &bin, binBer.pVal + pItem->GetOffset(), 1 );
    JS_BIN_bitString( &bin, &pBitString );
    unsigned char cID = pItem->GetId();

    char sClassBit[8 + 1] = "--------";
    char sIDBit[8 + 1] = "--------";
    char sPCBit[8 + 1] = "--------";
    char sTagBit[8 + 1] = "--------";

    unsigned char cLen = 0x00;
    int nLenSize = 0;
    unsigned char sLen[4];
    int nValueType = -1;

    pItem->getHeaderBin( &header );
    if( header.nLen < 2 ) return;

    if( pBitString && strlen( pBitString ) >= 8 )
    {
        sClassBit[0] = pBitString[0];
        sClassBit[1] = pBitString[1];

        sIDBit[0] = pBitString[0];
        sIDBit[1] = pBitString[1];
        sIDBit[2] = pBitString[2];

        sPCBit[2] = pBitString[2];

        sTagBit[3] = pBitString[3];
        sTagBit[4] = pBitString[4];
        sTagBit[5] = pBitString[5];
        sTagBit[6] = pBitString[6];
        sTagBit[7] = pBitString[7];
    }

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
    strOffset = QString( "%1" ).arg( pItem->GetOffset(), 8, 16, QLatin1Char('0')).toUpper();

    QString strTagHex = QString( "%1" ).arg( pItem->tag_, 2, 16, QLatin1Char('0')).toUpper();

    berApplet->mainWindow()->infoText()->clear();
    berApplet->line();
    berApplet->info( QString( "== BER Information [Depth:%1]\n" ).arg(pItem->GetLevel()) );
    berApplet->line();
    berApplet->info( QString( "Header      : %1\n").arg( getHexString(header.pVal, header.nLen)));
    berApplet->info( QString( "[T]         : 0x%1 = 0b%2\n" ).arg(getHexString(bin.pVal,1), nFieldWidth ).arg(pBitString) );
    berApplet->info( QString( "Class       : %1 = 0b%2\n").arg( pItem->GetClassString(), nFieldWidth -2).arg( sClassBit ));
    berApplet->info( QString( "ID          : 0x%1 = 0b%2\n").arg( getHexString( &cID, 1), nFieldWidth ).arg( sIDBit ));
    berApplet->info( QString( "P/C         : %1 = 0b%2\n").arg(strPC, nFieldWidth - 2).arg( sPCBit ));
    berApplet->info( QString( "Tag         : %1 = 0b%2 (0x%3)\n")
                        .arg( pItem->GetTagString(), nFieldWidth - 2 )
                        .arg( sTagBit )
                        .arg( strTagHex ) );

    if( pItem->GetIndefinite() == true )
    {
        berApplet->info( QString( "Length      : %1 = %2 Bytes\n" ).arg( "Indefinite", nFieldWidth - 2 ).arg(pItem->GetLength() - 2));
    }
    else
    {
        berApplet->info( QString( "Length      : 0x%1 = %2 Bytes\n" ).arg( getHexString(sLen, nLenSize), nFieldWidth ).arg(pItem->GetLength()));
    }

    berApplet->info( QString( "Offset      : 0x%1 = %2\n" ).arg( strOffset, nFieldWidth ).arg(pItem->GetOffset()));

    QString strVal = pItem->GetValueString( &binBer, &nValueType, nWidth );

    if( nValueType != JS_VALUE_HEX )
    {
        pItem->getValueBin( &binBer, &binVal );

        if( nValueType == JS_VALUE_BITSTRING  )
        {
            BIN binInt = {0,0};
            int nUnused = binVal.pVal[0];
            int nBitBytes = binVal.nLen - 1;

            int nBitLen = ( nBitBytes * 8 ) - nUnused;
            JS_BIN_intToBin( nBitLen, &binInt );

            berApplet->info( QString( "Unused Bits : 0x%1 = %2 Bits\n" ).arg(getHexString( &binVal.pVal[0], 1), nFieldWidth ).arg( nUnused));
            berApplet->info( QString( "Bit Length  : 0x%1 = %2 Bits\n" ).arg( getHexString( &binInt ), nFieldWidth ).arg( nBitLen ));

            JS_BIN_reset( &binInt );
        }

        berApplet->line();
        berApplet->info( "-- Print Value\n" );
        berApplet->line2();

        if( nValueType == JS_VALUE_OID )
        {
            const char *pSN = JS_PKI_getSNFromOID( strVal.toStdString().c_str());
            if( pSN ) berApplet->info( QString("[%1] ").arg( pSN ));
        }

        berApplet->info( strVal );
        berApplet->info( "\n" );

        berApplet->line();
        berApplet->info( "-- Hex Value\n" );
        berApplet->line2();
        berApplet->info( getHexStringArea( &binVal, nWidth ) );
    }
    else
    {
        berApplet->line();
        berApplet->info( "-- Hex Value\n" );
        berApplet->line2();
        berApplet->info( strVal );
    }

    berApplet->info( "\n" );
    berApplet->line();
    berApplet->mainWindow()->infoText()->moveCursor(QTextCursor::Start);
    if( pBitString ) JS_free( pBitString );
    JS_BIN_reset( &bin );
    JS_BIN_reset( &header );
    JS_BIN_reset( &binVal );
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
        berApplet->warningBox( tr( "There are no items selected."), this );
        return "";
    }


    const BIN& binBer = tree_model->getBER();
    BIN binData = {0,0};

    JS_BIN_set( &binData, &binBer.pVal[item->GetOffset()], item->GetHeaderSize() + item->GetLength() );
    QString strText = berApplet->mainWindow()->getInfo();
    strText += "\n=================================================================================\n";
    strText += getHexView( "All Data", &binData );
    JS_BIN_reset( &binData );

    return strText;
}


void BerTreeView::GetTableView(const BIN *pBer, BerItem *pItem)
{
    int table_idx = berApplet->mainWindow()->tableCurrentIndex();
    str_edit_.clear();

    if( table_idx == TABLE_IDX_XML )
    {
        CodeEditor *xmlEdit = berApplet->mainWindow()->rightXML();

        QTextCursor xml_cursor = xmlEdit->textCursor();
        QTextCharFormat format = xmlEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        xml_cursor.setCharFormat( format );
        xmlEdit->setTextCursor(xml_cursor);

        xmlEdit->clear();

        addEdit( 0, "<!-- XML Decoded Message -->\n" );
        setItemXML( 0, pItem );
        xmlEdit->setPlainText( str_edit_ );
        xmlEdit->moveCursor(QTextCursor::Start);;
    }
    else if( table_idx == TABLE_IDX_TXT )
    {
        CodeEditor *txtEdit = berApplet->mainWindow()->rightText();

        QTextCursor cursor = txtEdit->textCursor();
        QTextCharFormat format = txtEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        cursor.setCharFormat( format );
        txtEdit->setTextCursor(cursor);

        txtEdit->clear();

        addEdit( 0, "-- Text Decoded Message --\n" );
        setItemText( 0, pItem );
        txtEdit->setPlainText( str_edit_ );

        txtEdit->moveCursor(QTextCursor::Start);
    }
    else if( table_idx == TABLE_IDX_JSON )
    {
        CodeEditor *txtEdit = berApplet->mainWindow()->rightJSON();

        QTextCursor cursor = txtEdit->textCursor();
        QTextCharFormat format = txtEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        cursor.setCharFormat( format );
        txtEdit->setTextCursor(cursor);

        txtEdit->clear();

        addEdit( 0, "[\n" );
        setItemJSON( 1, pItem, false );
        addEdit( 0, "]\n" );
        txtEdit->setPlainText( str_edit_ );


        txtEdit->moveCursor(QTextCursor::Start);
    }
    else
    {
        int line = 0;
        BIN binPart = {0,0};
        QString text;
        QString hex;

        int len_len = 0;

        JS_BIN_set( &binPart, pBer->pVal + pItem->GetOffset(), pItem->GetHeaderSize() + pItem->GetLength() );

        QTableWidget* rightTable = berApplet->mainWindow()->rightTable();
        rightTable->setRowCount(0);

        for( int i = 0; i < binPart.nLen; i++ )
        {
            if( i % 16 == 0 )
            {
                rightTable->insertRow(line);
                rightTable->setRowHeight(line, 10);

                QString address;

                address = QString( "%1" ).arg( i + pItem->GetOffset(), 8, 16, QLatin1Char( '0') ).toUpper();
                QTableWidgetItem *addrItem = new QTableWidgetItem( address );
                addrItem->setFlags(addrItem->flags() & ~Qt::ItemIsSelectable );
                rightTable->setItem( line, 0, addrItem);
                rightTable->item( line, 0 )->setBackground( kAddrColor );
            }


            hex = QString( "%1").arg( binPart.pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
            rightTable->setItem( line, (i%16)+1, new QTableWidgetItem(hex));
            rightTable->item( line, (i%16) +1 )->setBackground(kValueColor);

            if( i== 0 )
            {
                rightTable->item( line, 1)->setBackground(kTagColor);
            }
            else if( i == 1 )
            {
                if( binPart.pVal[i] & JS_LEN_XTND )
                {
                    len_len = binPart.pVal[i] & JS_LEN_MASK;
                    rightTable->item( line, 2)->setBackground(kLenTypeColor);
                }
                else
                {
                    rightTable->item( line, i + 1 )->setBackground(kLenColor);
                }
            }
            else if( i <= (1 + len_len))
            {
                rightTable->item( line, i + 1 )->setBackground(kLenColor);
            }

            if( pItem->GetIndefinite() == true )
            {
                int nEnd = pItem->GetHeaderSize() + pItem->GetLength();
                if( i == (nEnd - 1) || i == (nEnd - 2) )
                    rightTable->item( line, i + 1 )->setBackground( kEOCColor );
            }

            text += getch( binPart.pVal[i]);

            if( i % 16 - 15 == 0 )
            {
                QTableWidgetItem *textItem = new QTableWidgetItem( text );
                textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
                rightTable->setItem( line, 17, textItem );
                rightTable->item( line, 17 )->setBackground(kTextColor);
                text.clear();
                line++;
            }
        }

        if( !text.isEmpty() )
        {
            QTableWidgetItem *textItem = new QTableWidgetItem( text );
            textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
            rightTable->setItem(line, 17, textItem);
            rightTable->item( line, 17 )->setBackground(kTextColor);
        }

        JS_BIN_reset(&binPart);
    }
}

void BerTreeView::GetTableFullView(const BIN *pBer, BerItem *pItem)
{
    pos_start_ = -1;
    pos_end_ = -1;
    str_edit_.clear();

    int table_idx = berApplet->mainWindow()->tableCurrentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *root = (BerItem *)tree_model->item(0,0);

    if( table_idx == TABLE_IDX_XML )
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
        setItemXML( 0, root, pItem );

        xmlEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            xml_cursor.setPosition( pos_start_ );
            xml_cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );


            QTextCharFormat format = xmlEdit->currentCharFormat();

            format.setForeground(Qt::blue);
            xml_cursor.setCharFormat( format );
            xml_cursor.mergeCharFormat( format );
            xml_cursor.clearSelection();

            xml_cursor.setPosition( pos_start_ + 512 );
            xmlEdit->setTextCursor(xml_cursor);
        }

        xmlEdit->update();
    }
    else if( table_idx == TABLE_IDX_TXT )
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

        txtEdit->update();
    }
    else if( table_idx == TABLE_IDX_JSON )
    {
        CodeEditor *txtEdit = berApplet->mainWindow()->rightJSON();
        txtEdit->clear();

        QTextCursor cursor = txtEdit->textCursor();
        QTextCharFormat format = txtEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        cursor.setCharFormat( format );
        txtEdit->setTextCursor(cursor);

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

        txtEdit->update();
    }
    else
    {
        int line = 0;

        QString text;
        QString hex;

        int len_len = 0;
        int start_col = 0;
        int start_row = 0;

        QTableWidget* rightTable = berApplet->mainWindow()->rightTable();
        rightTable->setRowCount(0);

        for( int i = 0; i < pBer->nLen; i++ )
        {
            int pos = 0;
            if( i % 16 == 0 )
            {
                rightTable->insertRow(line);
                rightTable->setRowHeight(line, 10);
                QString address;

                address = QString( "%1" ).arg( i, 8, 16, QLatin1Char( '0') ).toUpper();
                QTableWidgetItem *addrItem = new QTableWidgetItem( address );
                addrItem->setFlags(addrItem->flags() & ~Qt::ItemIsSelectable );
                rightTable->setItem( line, 0, addrItem);
                rightTable->item( line, 0 )->setBackground( kAddrColor );
            }

            hex = QString( "%1").arg( pBer->pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
            pos = (i%16) + 1;
            rightTable->setItem( line, pos, new QTableWidgetItem(hex));
            if( i== pItem->GetOffset() )
            {
                rightTable->item( line, pos)->setBackground(kTagColor);
                start_row = line;
                start_col = pos;
            }
            else if( i== pItem->GetOffset()+1 )
            {
                if( pBer->pVal[i] & JS_LEN_XTND )
                {
                    rightTable->item( line, pos)->setBackground(kLenTypeColor);
                    len_len = pBer->pVal[i] & JS_LEN_MASK;
                }
                else
                {
                    rightTable->item( line, pos)->setBackground(kLenColor);
                }
            }
            else if( (i > pItem->GetOffset() + 1 ) && (i <= (pItem->GetOffset() + 1 + len_len)))
            {
                rightTable->item( line, pos )->setBackground(kLenColor);
            }
            else if( (i > pItem->GetOffset() + 1 ) && ( i < pItem->GetOffset() + pItem->GetHeaderSize() + pItem->GetLength() ))
            {
                rightTable->item(line, pos )->setBackground(kValueColor);
            }

            if( pItem->GetIndefinite() == true )
            {
                int nEnd = pItem->GetOffset() + pItem->GetHeaderSize() + pItem->GetLength();
                if( i == (nEnd - 1) || i == (nEnd - 2) )
                    rightTable->item( line, pos )->setBackground( kEOCColor );
            }

            text += getch( pBer->pVal[i]);

            if( i % 16 - 15 == 0 )
            {
                QTableWidgetItem *textItem = new QTableWidgetItem( text );
                textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
                rightTable->setItem( line, 17, textItem );
                rightTable->item( line, 17 )->setBackground( kTextColor );
                text.clear();
                line++;
            }
        }

        if( !text.isEmpty() )
        {
            QTableWidgetItem *textItem = new QTableWidgetItem( text );
            textItem->setFlags(textItem->flags() & ~Qt::ItemIsSelectable );
            rightTable->setItem( line, 17, textItem );

            rightTable->item( line, 17 )->setBackground( kTextColor );
        }

        QTableWidgetItem *item = rightTable->item( start_row, start_col );
        rightTable->scrollToItem( item, ScrollHint::PositionAtCenter );
    }

}

void BerTreeView::copy()
{
    BerItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There are no items selected."), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();

    QString strLog = berApplet->mainWindow()->getInfo();
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
    BerItem* item = currentItem();

    if( item != NULL )
    {
        if( item->GetTag() == 0x00 ) return;

        menu.addAction(tr("Copy Information"), this, SLOT(copy()));
        menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
        menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
        menu.addAction(tr("Save node"), this, SLOT(SaveNode()));
        menu.addAction(tr("Save node value"), this, SLOT(SaveNodeValue()));

        QAction *pInsertAct = NULL;
        QAction *pEditAct = NULL;
        QAction *pDeleteAct = NULL;

        if( item->isConstructed() )
        {
            pInsertAct = menu.addAction( tr( "Insert value" ), this, SLOT(InsertBER()));
        }
        else
        {
            pEditAct = menu.addAction(tr("Edit value"), this, SLOT(EditValue()));
        }

        if( item->parent() )
            pDeleteAct = menu.addAction( tr("Delete value" ), this, SLOT(DeleteBER()));

        if( berApplet->isLicense() == false )
        {
            pInsertAct->setEnabled( false );
            pEditAct->setEnabled( false );
            pDeleteAct->setEnabled( false );
        }

        if( item->GetTag() == JS_OCTETSTRING || item->GetTag() == JS_BITSTRING )
        {
            if( item->hasChildren() == false )
                menu.addAction( tr("Expand value"), this, SLOT(ExpandValue()));
        }
    }

    menu.exec(QCursor::pos());
}

void BerTreeView::CopyAsHex()
{
    char *pHex = NULL;
    BerItem* item = currentItem();
    if( item == NULL )
    {
        berApplet->warningBox( tr( "There are no items selected."), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binData = {0,0};
    BerModel *tree_model = (BerModel *)model();

    const BIN& binBer = tree_model->getBER();
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
        berApplet->warningBox( tr( "There are no items selected."), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    BIN binData = {0,0};
    BerModel *tree_model = (BerModel *)model();

    const BIN& binBer = tree_model->getBER();
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
    int ret = 0;
    BIN binBER = {0,0};
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    if( tree_model == NULL ) return;

    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    if( item == NULL ) return;

    // 기존에 열었던 아이템 먼저 제거
    item->removeRow(0);

    int offset = item->GetOffset();
    int len = item->GetLength();
    int start = 0;
    binBER = tree_model->getBER();

    if( len <= 0 ) return;

    if( item->GetTag() == JS_BITSTRING )
    {
        offset += 1; // skip unused bits
        len -= 1;
    }

    start = offset;
    start += item->GetHeaderSize();

    if( JS_BER_isExpandable( &binBER.pVal[start], len ) != 1 )
    {
        ret = -1;
        goto end;
    }

    // Expand case (BitString or OctetString )  definite value only
    tree_model->parseConstruct( start, item, false );

end :
    if( ret < 0 )
    {
        berApplet->warningBox( tr("This is not BER encoded data"), this );
        return;
    }

    onItemClicked( index );
    expand( index );
}

const QString BerTreeView::SaveNode()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return "";

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    const BIN& binBer = tree_model->getBER();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str());
    JS_BIN_reset( &binData );

    return fileName;
}

void BerTreeView::SaveNodeValue()
{
    QString strPath;
    QString fileName = berApplet->findSaveFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    const BIN& binBer = tree_model->getBER();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset() + item->GetHeaderSize(), item->GetValLength() );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str());
    JS_BIN_reset(&binData);
}

void BerTreeView::EditValue()
{
    int ret = 0;
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), this );
        return;
    }

    EditValueDlg editValueDlg;
    editValueDlg.setHeadLabel( tr("Edit BER") );
    editValueDlg.setItem( item );
    ret = editValueDlg.exec();
}

void BerTreeView::InsertBER()
{
    int ret = 0;
    BIN binData = {0,0};

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    if( item->isConstructed() == false ) return;

    MakeBerDlg makeBer;
    makeBer.setHeadLabel( tr( "Insert BER" ));

    ret = makeBer.exec();

    if( ret == QDialog::Accepted )
    {
        bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), this, false );
        if( bVal == false ) return;

        QString strData = makeBer.getData();
        bool bFirst = makeBer.mFirstSetCheck->isChecked();

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        const BerItem* newItem = tree_model->addItem( item, bFirst, &binData );
        if( newItem )
        {
            int nOffset = newItem->offset_;

            berApplet->mainWindow()->reloadData();
            const BerItem *findItem = tree_model->findItemByOffset( nullptr, nOffset );
            if( findItem )
            {
                if( findItem->parent() ) expand( findItem->parent()->index() );

                QModelIndex idx = findItem->index();
                clicked( idx );
                setCurrentIndex( idx );
                expand( idx );
            }
        }
    }

end:
    JS_BIN_reset( &binData );
}

void BerTreeView::DeleteBER()
{
    int ret = 0;
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BerItem* parent = (BerItem *)item->parent();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no item to select" ), this );
        return;
    }

    if( item->parent() == nullptr )
    {
        berApplet->warningBox( tr( "Top-level items cannot be deleted" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr("Are you sure you want to delete it?"), this, true );
    if( bVal == false ) return;

    ret = tree_model->removeItem( item );
    if( ret == JSR_OK )
    {
        if( parent )
        {
            int nOffset = parent->GetOffset();

            berApplet->mainWindow()->reloadData();

            const BerItem *findItem = tree_model->findItemByOffset( nullptr, nOffset );
            if( findItem )
            {
                if( findItem->parent() ) expand( findItem->parent()->index() );

                QModelIndex idx = findItem->index();
                clicked( idx );
                setCurrentIndex( idx );
                expand( idx );
            }
        }
    }
}

void BerTreeView::addEdit( int level, const QString& strMsg )
{
    if( level > 0 )
    {
        QString strEmpty = QString( "%1" ).arg( " ", 4 * level, QLatin1Char( ' ' ));
        str_edit_ += strEmpty;
    }

    str_edit_ += strMsg;
}

void BerTreeView::setItemText( int level, BerItem* item, BerItem* setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    BerModel *tree_model = (BerModel *)model();
    const BIN& binBer = tree_model->getBER();
    QString strName = item->GetTagXMLString();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isConstructed() || item->hasChildren() )
    {
        if( strName == "CONTEXT" )
        {
            addEdit( level, QString("CONTEXT_%1 {\n").arg( item->GetTag() ) );
        }
        else
        {
            addEdit( level, QString("%1 {\n").arg( strName ) );
        }

        while( 1 )
        {
            BerItem* child = (BerItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemText( level + 1, child, setItem );
        }

        addEdit( level, "}\n" );
    }
    else
    {
        QString strValue = item->GetValueString( &binBer );

        if( strName == "NULL_TAG" ) strName = "NULL";

        addEdit( level, QString( "%1" ).arg( strName ) );

        if( strName == "NULL")
            addEdit( 0, " =\n" );
        else
            addEdit( 0, QString( " = %1\n" ).arg( strValue ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

void BerTreeView::setItemXML( int level, BerItem* item, BerItem* setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    BerModel *tree_model = (BerModel *)model();
    const BIN& binBer = tree_model->getBER();
    QString strName = item->GetTagXMLString();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isConstructed() || item->hasChildren() )
    {
        if( strName == "CONTEXT" )
        {
            addEdit( level, QString( "<CONTEXT_%1>\n" ).arg(item->GetTag()) );
        }
        else
        {
            addEdit( level, QString("<%1>\n").arg( strName) );
        }

        while( 1 )
        {
            BerItem* child = (BerItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemXML( level + 1, child, setItem );
        }

        addEdit( level, QString("</%1>\n").arg( strName ) );
    }
    else
    {
        QString strValue = item->GetValueString( &binBer );

        if( strName == "OBJECT_IDENTIFIER" )
        {
            QString strComment;
            QString strDesc;

            strComment = JS_PKI_getLNFromOID( strValue.toStdString().c_str() );
            strDesc = JS_PKI_getSNFromOID( strValue.toStdString().c_str() );

            addEdit( level, QString( "<%1" ).arg( strName ) );

            if( strComment.length() > 0 )
            {
                addEdit( 0, " Comment=" );
                addEdit( 0, QString("\"%1\"").arg( strComment) );
            }

            if( strDesc.length() > 0 )
            {
                addEdit( 0, " Description=" );
                addEdit( 0, QString("\"%1\"").arg( strDesc) );
            }

            addEdit( 0, ">" );
            addEdit( 0, QString( "%1" ).arg( strValue ) );
            addEdit( 0, QString( "</%1>\n" ).arg( strName ) );
        }
        else if( strName == "NULL_TAG" )
        {
            addEdit( level, QString( "<NULL/>\n" ));
        }
        else
        {
            addEdit( level, QString( "<%1>" ).arg( strName ) );
            addEdit( 0, QString( "%1" ).arg( strValue ) );
            addEdit( 0, QString( "</%1>\n" ).arg( strName ) );
        }
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

void BerTreeView::setItemJSON( int level, BerItem* item, bool bNext, BerItem* setItem )
{
    int pos = 0;

    if( item == NULL ) return;

    BerModel *tree_model = (BerModel *)model();
    const BIN& binBer = tree_model->getBER();
    QString strName = item->GetTagXMLString();

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isConstructed() || item->hasChildren() )
    {
        if( strName == "CONTEXT" )
        {
            addEdit( level, QString( "\"CONTEXT_%1\": {\n" ).arg( item->GetTag() ));
        }
        else
        {
            addEdit( level, QString("\"%1\": {\n").arg( strName) );
        }

        while( 1 )
        {
            bool bNext = false;
            BerItem* child = (BerItem *)item->child( pos );
            if( child == NULL ) break;

            pos++;
            BerItem* next = (BerItem *)item->child( pos );
            if( next ) bNext = true;

            setItemJSON( level + 1, child, bNext, setItem );
        }


        addEdit( level, QString( "}" ) );
        if( bNext == true ) addEdit( 0, "," );
        addEdit( 0, QString( "\n" ));
    }
    else
    {
        QString strValue = item->GetValueString( &binBer );

        if( strName == "NULL_TAG" )
        {
            addEdit( level, "\"NULL\"" );
        }
        else
        {
            addEdit( level, QString( "\"%1\": " ).arg( strName ) );

            if( strName == "INTEGER" )
            {
                addEdit( 0, QString( "%1" ).arg( strValue ) );
            }
            else if( strName == "BOOLEAN" )
            {
                addEdit( 0, QString( "%1" ).arg( strValue ).toLower() );
            }
            else if( strName == "OBJECT_IDENTIFIER" || strName == "PRINTABLE_STRING" || strName == "UTF8_STRING")
            {
                addEdit( 0, QString( "\"%1\"" ).arg( strValue ) );
            }
            else
            {
                addEdit( 0, QString( "%1" ).arg( strValue ) );
            }
        }

        if( bNext == true ) addEdit( 0, "," );
        addEdit( 0, QString( "\n" ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}
