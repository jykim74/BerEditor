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
#include "BasicXMLSyntaxHighlighter.h"

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
    BerModel *tree_model = (BerModel *)model();
    const BIN& binBer = tree_model->getBER();

    BIN bin = {0,0};
    BIN header = {0,0};
    BIN binVal = {0,0};

    char *pBitString = NULL;
    JS_BIN_set( &bin, binBer.pVal + pItem->GetOffset(), 1 );
    JS_BIN_bitString( &bin, &pBitString );
    unsigned char cID = pItem->GetId();
    char sID[3+1];
    unsigned char cLen = 0x00;
    int nLenSize = 0;
    unsigned char sLen[4];

    pItem->getHeaderBin( &header );
    if( header.nLen < 2 ) return;

    memset( sID, 0x00, sizeof(sID));
    if( pBitString )
    {
        memcpy( sID, pBitString, 3 );
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

    berApplet->mainWindow()->infoText()->clear();
    berApplet->info( "=================================================================================\n" );
    berApplet->info( QString( "== BER Information [Depth:%1]\n" ).arg(pItem->GetLevel()) );
    berApplet->info( "=================================================================================\n" );
    berApplet->info( QString( "Header      : %1\n").arg( getHexString(header.pVal, header.nLen)));
    berApplet->info( QString( "[T]         : 0x%1 - %2\n" ).arg(getHexString(bin.pVal,1)).arg(pBitString) );
    berApplet->info( QString( "Class       : %1\n").arg( pItem->GetClassString()));
    berApplet->info( QString( "ID          : 0x%1 - %2\n").arg( getHexString( &cID, 1) ).arg( sID ));
    berApplet->info( QString( "P/C         : %1\n").arg(strPC));
    berApplet->info( QString( "Tag         : 0x%1 - %2\n").arg( pItem->GetTag(), 2, 16, QChar('0')).arg(pItem->GetTagString()));
    berApplet->info( QString( "Offset      : %1 - %2\n" ).arg( strOffset ).arg(pItem->GetOffset()));
    berApplet->info( QString( "Length      : 0x%1 - %2 Bytes\n" ).arg( getHexString(sLen, nLenSize) ).arg(pItem->GetLength()));
    berApplet->info( QString( "Level       : %1\n").arg( pItem->GetLevel() ));

    QString strVal = pItem->GetValueString( &binBer, nWidth );

    if( pItem->GetTag() == JS_BITSTRING )
    {
        pItem->getValueBin( &binBer, &binVal );
        berApplet->info( QString( "Bit Length  : %1 Bits\n" ).arg(strVal.length()));
        berApplet->info( QString( "Unused Bits : 0x%1 - %2 Bits\n" ).arg(getHexString( &binVal.pVal[0], 1)).arg(binVal.pVal[0]));
    }

    berApplet->info( "=================================================================================\n" );
    berApplet->info( strVal );

    if( pItem->GetTag() == JS_BITSTRING )
    {
        berApplet->info( "\n" );
        berApplet->info( "=================================================================================\n" );
        berApplet->info( "== Hex Value\n" );
        berApplet->info( "=================================================================================\n" );
        berApplet->info( getHexStringArea(&binVal.pVal[1], binVal.nLen - 1, nWidth ));
    }

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
        QTextEdit *xmlEdit = berApplet->mainWindow()->rightXML();

        QTextCursor xml_cursor = xmlEdit->textCursor();
        QTextCharFormat format = xmlEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        xml_cursor.setCharFormat( format );
        xmlEdit->setTextCursor(xml_cursor);

        xmlEdit->clear();

        setXML( 0, "<!-- XML Decoded Message -->\n" );
        setItemXML( 0, pItem );
        xmlEdit->setPlainText( str_edit_ );
        xmlEdit->moveCursor(QTextCursor::Start);;
    }
    else if( table_idx == TABLE_IDX_TXT )
    {
        QTextEdit *txtEdit = berApplet->mainWindow()->rightText();

        QTextCursor cursor = txtEdit->textCursor();
        QTextCharFormat format = txtEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        cursor.setCharFormat( format );
        txtEdit->setTextCursor(cursor);

        txtEdit->clear();

        setText( 0, "-- Text Decoded Message --\n" );
        setItemText( 0, pItem );
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
                QString address;

                address = QString( "%1" ).arg( i + pItem->GetOffset(), 8, 16, QLatin1Char( '0') ).toUpper();
                rightTable->setItem( line, 0, new QTableWidgetItem( address ));
                rightTable->item( line, 0 )->setBackground( kAddrColor );
            }


            hex = QString( "%1").arg( binPart.pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
            rightTable->setItem( line, (i%16)+1, new QTableWidgetItem(hex));
            rightTable->item( line, (i%16) +1 )->setBackground(kValueColor);

            if( i== 0 )
            {
                rightTable->item( line, 1)->setBackground(kTagColor);
            }
            else if( i== 1 )
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


            text += getch( binPart.pVal[i]);

            if( i % 16 - 15 == 0 )
            {
                rightTable->setItem( line, 17, new QTableWidgetItem(text));
                rightTable->item( line, 17 )->setBackground(kTextColor);
                text.clear();
                line++;
            }
        }

        if( !text.isEmpty() )
        {
            rightTable->setItem(line, 17, new QTableWidgetItem(text));
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
        QTextEdit *xmlEdit = berApplet->mainWindow()->rightXML();
        xmlEdit->clear();

        QTextCursor xml_cursor = xmlEdit->textCursor();
        QTextCharFormat format = xmlEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        xml_cursor.setCharFormat( format );
        xmlEdit->setTextCursor(xml_cursor);

        setXML( 0, "<!-- XML Decoded Message -->\n" );
        setItemXML( 0, root, pItem );

        xmlEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            berApplet->log( QString( "Sel [%1:%2]").arg( pos_start_ ).arg( pos_end_ ));


            xml_cursor.setPosition( pos_start_ );
            xml_cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );

            QTextCharFormat format = xmlEdit->currentCharFormat();
//            format.setFontWeight(QFont::Bold);
            format.setForeground(Qt::blue);
            xml_cursor.setCharFormat( format );
            xml_cursor.clearSelection();
            xmlEdit->setTextCursor(xml_cursor);
        }
    }
    else if( table_idx == TABLE_IDX_TXT )
    {
        QTextEdit *txtEdit = berApplet->mainWindow()->rightText();
        txtEdit->clear();

        QTextCursor cursor = txtEdit->textCursor();
        QTextCharFormat format = txtEdit->currentCharFormat();
        //format.setFontWeight(QFont::Normal);
        format.setForeground(Qt::black);
        cursor.setCharFormat( format );
        txtEdit->setTextCursor(cursor);

        setText( 0, "-- Text Decoded Message --\n" );
        setItemText( 0, root, pItem );
        txtEdit->setPlainText( str_edit_ );

        if( pos_start_ >= 0 && pos_end_ > pos_start_ )
        {
            berApplet->log( QString( "Sel [%1:%2]").arg( pos_start_ ).arg( pos_end_ ));
            cursor.setPosition( pos_start_ );
            cursor.setPosition( pos_end_, QTextCursor::KeepAnchor );

            QTextCharFormat format = txtEdit->currentCharFormat();
            // format.setFontWeight(QFont::Bold);
            format.setForeground(Qt::blue);
            cursor.setCharFormat( format );
            cursor.clearSelection();
            txtEdit->setTextCursor(cursor);
        }
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
                QString address;

                address = QString( "%1" ).arg( i, 8, 16, QLatin1Char( '0') ).toUpper();
                rightTable->setItem( line, 0, new QTableWidgetItem( address ));
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

            text += getch( pBer->pVal[i]);

            if( i % 16 - 15 == 0 )
            {
                rightTable->setItem( line, 17, new QTableWidgetItem(text));
                rightTable->item( line, 17 )->setBackground( kTextColor );
                text.clear();
                line++;
            }
        }

        if( !text.isEmpty() )
        {
            rightTable->setItem(line, 17, new QTableWidgetItem(text));
            rightTable->item( line, 17 )->setBackground( kTextColor );
        }

        QTableWidgetItem *item = rightTable->item( start_row, start_col );
        rightTable->scrollToItem( item );
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
    menu.addAction(tr("Copy Information"), this, SLOT(copy()));
    menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
    menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
    menu.addAction(tr("Save node"), this, SLOT(SaveNode()));
    menu.addAction(tr("Save node value"), this, SLOT(SaveNodeValue()));



    /*
    if( berApplet->isLicense() )
        menu.addAction(tr("Edit value"), this, SLOT(EditValue()));
    */



    BerItem* item = currentItem();

    if( item != NULL )
    {
        QAction *pInsertAct = NULL;
        QAction *pEditAct = NULL;

        pEditAct = menu.addAction(tr("Edit value"), this, SLOT(EditValue()));

        if( item->isConstructed() )
        {
            pInsertAct = menu.addAction( tr( "Insert BER" ), this, SLOT(InsertBER()));
        }

        if( berApplet->isLicense() == false )
        {
            pInsertAct->setEnabled( false );
            pEditAct->setEnabled( false );
        }

        if( item->GetTag() == JS_OCTETSTRING || item->GetTag() == JS_BITSTRING )
            menu.addAction( tr("Expand value"), this, SLOT(ExpandValue()));
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
    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);

    // 기존에 열었던 아이템 먼저 제거
    item->removeRow(0);

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

    onItemClicked( index );
    expand( index );
}

void BerTreeView::SaveNode()
{
    QString strPath = berApplet->curFolder();
    QString fileName = findSaveFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    const BIN& binBer = tree_model->getBER();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset(), item->GetHeaderSize() + item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str());
    JS_BIN_reset( &binData );

    berApplet->setCurFile( fileName );
}

void BerTreeView::SaveNodeValue()
{
    QString strPath = berApplet->curFolder();
    QString fileName = findSaveFile( this, JS_FILE_TYPE_BER, strPath );
    if( fileName.length() < 1 ) return;

    QModelIndex index = currentIndex();

    BerModel *tree_model = (BerModel *)model();
    BerItem *item = (BerItem *)tree_model->itemFromIndex(index);
    BIN binData = {0,0};
    const BIN& binBer = tree_model->getBER();

    JS_BIN_set( &binData, binBer.pVal + item->GetOffset() + item->GetHeaderSize(), item->GetLength() );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str());
    JS_BIN_reset(&binData);

    berApplet->setCurFile( fileName );
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
        viewRoot();
        QModelIndex ri = tree_model->index(0,0);
        expand(ri);
/*
        showTextView();
        showXMLView();
*/
    }
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
    ret = makeBer.exec();

    if( ret == QDialog::Accepted )
    {
        bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure you want to add it?" ), this, false );
        if( bVal == false ) return;

        QString strData = makeBer.getData();
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        ret = tree_model->addItem( item, &binData );
        if( ret != 0 ) goto end;

        tree_model->parseTree();

        viewRoot();
        QModelIndex ri = tree_model->index(0,0);
        expand(ri);
    }

end:
    JS_BIN_reset( &binData );
}

void BerTreeView::setText( int level, const QString& strMsg )
{
    if( level > 0 )
    {
        QString strEmpty = QString( "%1" ).arg( " ", 4 * level, QLatin1Char( ' ' ));
        str_edit_ += strEmpty;
    }

    str_edit_ += strMsg;
}

void BerTreeView::setXML( int level, const QString& strMsg )
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

    if( item == setItem )
    {
        pos_start_ = str_edit_.length();
    }

    if( item->isConstructed() || item->hasChildren() )
    {
        setText( level, QString("%1 {\n").arg( item->text()) );

        while( 1 )
        {
            BerItem* child = (BerItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemText( level + 1, child, setItem );
        }

        setText( level, "}\n" );
    }
    else
    {
        QString strName = item->GetTagString();
        QString strValue = item->GetValueString( &binBer );

        setText( level, QString( "%1" ).arg( strName ) );
        setText( 0, QString( " = %1\n" ).arg( strValue ) );
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
        if( strName == "NODE" )
        {
            setXML( level, QString( "<%1 Sign=" ).arg(strName) );
            setXML( 0, QString( "\"%1\"" ).arg( item->GetTag() | item->GetId(), 2, 16, QLatin1Char('0')) );
            setXML( 0, QString( ">\n") );
        }
        else
        {
            setXML( level, QString("<%1>\n").arg( strName) );
        }

        while( 1 )
        {
            BerItem* child = (BerItem *)item->child( pos++ );
            if( child == NULL ) break;

            setItemXML( level + 1, child, setItem );
        }

        setXML( level, QString("</%1>\n").arg( strName ) );
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

            setXML( level, QString( "<%1" ).arg( strName ) );

            if( strComment.length() > 0 )
            {
                setXML( 0, " Comment=" );
                setXML( 0, QString("\"%1\"").arg( strComment) );
            }

            if( strDesc.length() > 0 )
            {
                setXML( 0, " Description=" );
                setXML( 0, QString("\"%1\"").arg( strDesc) );
            }

            setXML( 0, ">" );
        }
        else
        {
            setXML( level, QString( "<%1>" ).arg( strName ) );
        }

        setXML( 0, QString( "%1" ).arg( strValue ) );
        setXML( 0, QString( "</%1>\n" ).arg( strName ) );
    }

    if( item == setItem )
    {
        pos_end_ = str_edit_.length();
    }
}

/*
void BerTreeView::showTextView()
{
    BerModel *tree_model = (BerModel *)model();
    BerItem *root = (BerItem *)tree_model->item(0,0);

    QTextEdit *txtEdit = berApplet->mainWindow()->rightText();
    txtEdit->clear();

    showText( 0, "-- Text Decoded Message --\n", QColor(Qt::blue) );
    showItemText( root );
    txtEdit->moveCursor(QTextCursor::Start);
}

void BerTreeView::showXMLView()
{
    BerModel *tree_model = (BerModel *)model();
    BerItem *root = (BerItem *)tree_model->item(0,0);

    QTextEdit *xmlEdit = berApplet->mainWindow()->rightXML();
    xmlEdit->clear();

    showXML( 0, "<!-- XML Decoded Message -->\n", QColor(Qt::darkGreen) );
    showItemXML( root );
    xmlEdit->moveCursor(QTextCursor::Start);
}
*/
