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

void TTLVTreeView::viewRoot()
{
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    QModelIndex ri = tree_model->index(0,0);
    onItemClicked( ri );
    setExpanded( rootIndex(), true );
}

void TTLVTreeView::showRight()
{
    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    TTLVTreeItem  *rootItem = (TTLVTreeItem *)left_model->item(0);

    SettingsMgr *setMgr = berApplet->settingsMgr();

    if( setMgr->showPartOnly() == false )
        showRightFull( rootItem );
    else
        showRightPart( rootItem );

    setExpanded( rootIndex(), true );
}

void TTLVTreeView::onItemClicked( const QModelIndex& index )
{
    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    TTLVTreeItem *item = (TTLVTreeItem *)left_model->itemFromIndex(index);

    SettingsMgr *setMgr = berApplet->settingsMgr();
    int nWidth = setMgr->getHexAreaWidth();

    if( setMgr->showPartOnly() == false )
        showRightFull( item );
    else
        showRightPart( item );

    getInfoView( item, nWidth );
}

void TTLVTreeView::leftContextMenu( QPoint point )
{
    QMenu menu(this);

    menu.addAction(tr("Copy Information"), this, SLOT(copy()));
    menu.addAction(tr("Copy as hex"), this, SLOT(CopyAsHex()));
    menu.addAction(tr("Copy as base64"), this, SLOT(CopyAsBase64()));
    menu.addAction( tr("Edit"), this, &TTLVTreeView::editItem );
    menu.addAction( tr("SaveItem"), this, &TTLVTreeView::saveItem );
    menu.addAction( tr("SaveItemValue"), this, &TTLVTreeView::saveItemValue );

    TTLVTreeItem* item = currentItem();

    if( item->isStructure() == true )
    {
        menu.addAction( tr( "AddTTLV" ), this, &TTLVTreeView::AddTTLV );
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

void TTLVTreeView::showRightFull( TTLVTreeItem *pItem )
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

    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    BIN TTLV = left_model->getTTLV();


    int row_cnt = rightTable->rowCount();
    for( int k=0; k < row_cnt; k++ )
        rightTable->removeRow(0);

    for( int i = 0; i < TTLV.nLen; i++ )
    {
        int pos = 0;
        int len = 0;
        int pad = 0;

        if( i % 16 == 0 )
        {
            rightTable->insertRow(line);
            QString address;
            address = QString( "%1" ).arg( i, 8, 16, QLatin1Char( '0' ));
            rightTable->setItem( line, 0, new QTableWidgetItem(address));
            rightTable->item( line, 0 )->setBackgroundColor( QColor(220,220,250) );
        }

        hex = QString( "%1" ).arg( TTLV.pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
        pos = (i%16) + 1;
        rightTable->setItem( line, pos, new QTableWidgetItem(hex));

        len = pItem->getLengthInt();
        pad = 8 - (len % 8);
        if( pad == 8 ) pad = 0;

        if( i >= pItem->getOffset() && i < pItem->getOffset() + 3 )
        {
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

        if( i % 16 - 15 == 0 )
        {
            rightTable->setItem( line, 17, new QTableWidgetItem(text));
            rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() )
    {
        rightTable->setItem( line, 17, new QTableWidgetItem(text));
        rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
    }

//    getInfoView( pItem );
}

void TTLVTreeView::showRightPart( TTLVTreeItem *pItem )
{
    int line = 0;

    QString text;
    QString hex;
    QColor green(Qt::green);
    QColor yellow(Qt::yellow);
    QColor cyan(Qt::cyan);
    QColor lightGray(Qt::lightGray);
    BIN     binPart = {0,0};

    int length = 0;
    int pad = 0;

    QTableWidget* rightTable = berApplet->mainWindow()->rightTable();
    TTLVTreeModel *left_model = (TTLVTreeModel *)model();
    BIN TTLV = left_model->getTTLV();

    length = pItem->getLengthInt();
    pad = 8 - length % 8;
    if( pad == 8 ) pad = 0;

    JS_BIN_set( &binPart, TTLV.pVal + pItem->getOffset(), 8 + length + pad );

    int row_cnt = rightTable->rowCount();
    for( int k=0; k < row_cnt; k++ )
        rightTable->removeRow(0);

    for( int i = 0; i < binPart.nLen; i++ )
    {
        int pos = 0;

        if( i % 16 == 0 )
        {
            rightTable->insertRow(line);
            QString address;

            address = QString( "%1" ).arg( i, 8, 16, QLatin1Char( '0' ));
            rightTable->setItem( line, 0, new QTableWidgetItem(address));
            rightTable->item( line, 0 )->setBackgroundColor( QColor(220,220,250) );
        }

        hex = QString( "%1" ).arg( TTLV.pVal[i], 2, 16, QLatin1Char('0') ).toUpper();
        pos = (i%16) + 1;
        rightTable->setItem( line, pos, new QTableWidgetItem(hex));

        if( i >= 0 && i < 3 )
        {
            rightTable->item( line, pos )->setBackgroundColor(green);
        }
        else if( i == 3 )
        {
            rightTable->item( line, pos )->setBackgroundColor(yellow);
        }
        else if( i >= 4 && i < 8 )
        {
            rightTable->item( line, pos )->setBackgroundColor(cyan);
        }
        else if( i >= 8 && i < 8 + length )
        {
            rightTable->item( line, pos )->setBackgroundColor(kValueColor);
        }
        else if( i >= (8 + length ) && i < ( 8 + length + pad ))
        {
            rightTable->item( line, pos )->setBackgroundColor(lightGray);
        }


        text += getch( binPart.pVal[i] );

        if( i % 16 - 15 == 0 )
        {
            rightTable->setItem( line, 17, new QTableWidgetItem(text));
            rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
            text.clear();
            line++;
        }
    }

    if( !text.isEmpty() )
    {
        rightTable->setItem( line, 17, new QTableWidgetItem(text));
        rightTable->item( line, 17 )->setBackgroundColor(QColor(210,240,210));
    }

//    getInfoView( pItem );

    JS_BIN_reset( &binPart );
}

void TTLVTreeView::getInfoView(TTLVTreeItem *pItem, int nWidth )
{
    BIN binTTLV = berApplet->getTTLV();
    BIN binHeader = {0,0};

    pItem->getHeader( &binHeader );

    berApplet->mainWindow()->infoClear();

    berApplet->info( "========================================================================\n" );
    berApplet->info( "== TTLV Information\n" );
    berApplet->info( "========================================================================\n" );

    berApplet->info( QString( "Header   : %1\n" ).arg( getHexString( &binHeader )));
    berApplet->info( QString( "Tag      : 0x%1 - %2\n" ).arg( pItem->getTagHex() ).arg( pItem->getTagName() ));
    berApplet->info( QString( "Type     : 0x%1 - %2\n").arg( pItem->getTypeHex() ).arg( pItem->getTypeName() ));
    berApplet->info( QString( "Length   : 0x%1 - %2 Bytes\n" ).arg( pItem->getLengthHex() ).arg( pItem->getLengthInt() ));
    berApplet->info( QString( "Offset   : 0x%1 - %2\n").arg( pItem->getOffset(), 0, 16).arg( pItem->getOffset()) );
    berApplet->info( "========================================================================\n" );
    berApplet->info( QString( "%1").arg( pItem->getPrintValue( &binTTLV, nWidth ) ) );

    JS_BIN_reset( &binHeader );
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

void TTLVTreeView::AddTTLV()
{
    int ret = 0;
    BIN binData = {0,0};
    MakeTTLVDlg makeTTLV;

    TTLVTreeModel *ttlv_model = (TTLVTreeModel *)model();
    TTLVTreeItem* item = currentItem();

    if( item->isStructure() == false )
    {
        berApplet->warningBox( tr( "The item is not structured" ), this );
        return;
    }

    ret = makeTTLV.exec();

    if( ret == QDialog::Accepted )
    {
        QString strData = makeTTLV.getData();
        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

        ret = ttlv_model->addItem( item, &binData );

        JS_BIN_reset( &binData );

        if( ret == 0 )
        {
            ttlv_model->parseTree();
            QModelIndex ri = ttlv_model->index(0,0);
            expand(ri);

            showTextView();
            showXMLView();
        }
    }
}

void TTLVTreeView::editItem()
{
    int ret = 0;
    EditTTLVDlg editTTLV;
    ret = editTTLV.exec();
    if( ret == QDialog::Accepted )
    {
        TTLVTreeModel *ttlv_model = (TTLVTreeModel *)model();

        ttlv_model->parseTree();
        QModelIndex ri = ttlv_model->index(0,0);
        expand(ri);

        showTextView();
        showXMLView();
    }
}

void TTLVTreeView::saveItem()
{
    QFileDialog fileDlg(this, tr("Save as..."));
    fileDlg.setAcceptMode(QFileDialog::AcceptSave);
    fileDlg.setDefaultSuffix("ber");
    if( fileDlg.exec() != QDialog::Accepted )
        return;

    QString fileName = fileDlg.selectedFiles().first();

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return;

    BIN binData = {0,0};
    BIN binTTLV = berApplet->getTTLV();
    BIN binHeader = {0,0};
    BIN binValue = {0,0};

    pItem->getHeader( &binHeader );
    pItem->getValue( &binTTLV, &binValue );

    JS_BIN_appendBin( &binData, &binHeader );
    JS_BIN_appendBin( &binData, &binValue );

    JS_BIN_fileWrite( &binData, fileName.toStdString().c_str() );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binHeader );
    JS_BIN_reset( &binValue );
}

void TTLVTreeView::saveItemValue()
{
    QFileDialog fileDlg(this, tr("Save as..."));
    fileDlg.setAcceptMode(QFileDialog::AcceptSave);
    fileDlg.setDefaultSuffix("ber");
    if( fileDlg.exec() != QDialog::Accepted )
        return;

    QString fileName = fileDlg.selectedFiles().first();
    BIN binTTLV = berApplet->getTTLV();
    BIN binValue = {0,0};

    TTLVTreeItem *pItem = currentItem();
    if( pItem == NULL ) return;

    pItem->getValue( &binTTLV, &binValue );

    JS_BIN_fileWrite( &binValue, fileName.toStdString().c_str() );
    JS_BIN_reset( &binValue );
}

void TTLVTreeView::showItemText( TTLVTreeItem* item )
{
    int row = 0;
    int col = 0;
    int pos = 0;
    int level = 0;

    if( item == NULL ) return;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    BIN binTTLV = tree_model->getTTLV();

    row = item->row();
    col = item->column();
    level = item->getLevel();


    if( item->getTypeHex() == "01" )
    {
        showText( level, QString("%1 {\n").arg( item->text()), QColor(Qt::darkCyan) );

        while( 1 )
        {
            TTLVTreeItem* child = (TTLVTreeItem *)item->child( pos++ );
            if( child == NULL ) break;

            showItemText( child );
        }

        showText( level, "}\n", QColor(Qt::darkCyan) );
    }
    else
    {
        QString strName = item->getTagName();
        QString strValue = item->getPrintValue( &binTTLV );

        showText( level, QString( "%1" ).arg( strName ), QColor(Qt::darkMagenta) );
        showText( 0, QString( " = %1\n" ).arg( strValue ) );
    }
}

void TTLVTreeView::showItemXML( TTLVTreeItem* item )
{
    int row = 0;
    int col = 0;
    int pos = 0;
    int level = 0;

    if( item == NULL ) return;

    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    BIN binTTLV = tree_model->getTTLV();

    row = item->row();
    col = item->column();
    level = item->getLevel();

    QString strName = item->getTagName();

    if( item->getTypeHex() == "01" )
    {
        showXML( level, QString("<%1>\n").arg( strName), QColor(Qt::darkCyan) );

        while( 1 )
        {
            TTLVTreeItem* child = (TTLVTreeItem *)item->child( pos++ );
            if( child == NULL ) break;

            showItemXML( child );
        }

        showXML( level, QString("</%1>\n").arg( strName ), QColor(Qt::darkCyan) );
    }
    else
    {
        QString strValue = item->getPrintValue( &binTTLV );

        showXML( level, QString( "<%1>" ).arg( strName ), QColor(Qt::darkMagenta) );
        showXML( 0, QString( "%1" ).arg( strValue ) );
        showXML( 0, QString( "</%1>\n" ).arg( strName ), QColor(Qt::darkMagenta) );
    }
}

void TTLVTreeView::showText( int level, const QString& strMsg, QColor cr, bool bBold )
{
    QString strEmpty = QString( "%1" ).arg( " ", 4 * level, QLatin1Char( ' ' ));
    QTextEdit *txtEdit = berApplet->mainWindow()->rightText();

    QTextCursor cursor = txtEdit->textCursor();
    QTextCharFormat format;
    format.setForeground( cr );
    if( bBold )
        format.setFontWeight(QFont::Bold);
    else
        format.setFontWeight(QFont::Normal);

    cursor.mergeCharFormat( format );

    if( level > 0 ) cursor.insertText( strEmpty );
    cursor.insertText( strMsg );

    txtEdit->setTextCursor( cursor );
    txtEdit->repaint();
}

void TTLVTreeView::showXML( int level, const QString& strMsg, QColor cr, bool bBold )
{
    QString strEmpty = QString( "%1" ).arg( " ", 4 * level, QLatin1Char( ' ' ));
    QTextEdit *xmlEdit = berApplet->mainWindow()->rightXML();


    QTextCursor cursor = xmlEdit->textCursor();
    QTextCharFormat format;
    format.setForeground( cr );

    if( bBold )
        format.setFontWeight(QFont::Bold);
    else
        format.setFontWeight(QFont::Normal);

    cursor.mergeCharFormat( format );

    if( level > 0 ) cursor.insertText( strEmpty );
    cursor.insertText( strMsg );

    xmlEdit->setTextCursor( cursor );
    xmlEdit->repaint();
}

void TTLVTreeView::showTextView()
{
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    TTLVTreeItem *root = (TTLVTreeItem *)tree_model->item(0,0);

    QTextEdit *txtEdit = berApplet->mainWindow()->rightText();
    txtEdit->clear();

    showText( 0, "-- Text Decoded Message --\n", QColor(Qt::blue) );
    showItemText( root );
    txtEdit->moveCursor(QTextCursor::Start);
}

void TTLVTreeView::showXMLView()
{
    TTLVTreeModel *tree_model = (TTLVTreeModel *)model();
    TTLVTreeItem *root = (TTLVTreeItem *)tree_model->item(0,0);

    QTextEdit *xmlEdit = berApplet->mainWindow()->rightXML();
    xmlEdit->clear();

    showXML( 0, "<!-- XML Decoded Message -->\n", QColor(Qt::darkGreen) );
    showItemXML( root );
    xmlEdit->moveCursor(QTextCursor::Start);
}
