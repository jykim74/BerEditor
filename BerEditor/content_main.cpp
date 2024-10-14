#include <QFileInfo>
#include <QTextStream>
#include <QDir>
#include <QToolBar>
#include <QtPrintSupport/qtprintsupportglobal.h>
#include <QtHelp/QHelpEngine>

#include "content_main.h"
#include "common.h"
#include "ber_applet.h"
#include "js_http.h"
#include "mainwindow.h"

#if defined(QT_PRINTSUPPORT_LIB)
#include <QtPrintSupport/qtprintsupportglobal.h>
#if QT_CONFIG(printer)
#if QT_CONFIG(printdialog)
#include <QPrintDialog>
#endif
#include <QPrinter>
#if QT_CONFIG(printpreviewdialog)
#include <QPrintPreviewDialog>
#endif
#endif
#endif

static const QString kDoc = "DOC";
static const QString kRFC = "RFC";
static const QString kASN1 = "ASN1";
static const QString kPKIX = "PKIX";

QString kRFCHost = "https://www.rfc-editor.org/rfc/inline-errata";
QString kPKIXHost = "https://www.rfc-editor.org/rfc";

static const QStringList kRFCList = { "RFC5280", "RFC5480", "RFC4210", "RFC4211", "RFC2560", "RFC3161", "RFC8894" };
static const QStringList kPKIXList = { "PKCS#1:RFC8017", "PKCS#3:RFC2631", "PKCS#5:RFC2898", "PKCS#7:RFC5652",
                                      "PKCS#8:RFC5208", "PKCS#10:RFC2986", "PKCS#12:RFC7292" };

ContentMain::ContentMain(QWidget *parent) :
    QMainWindow(parent)
{
    setupUi(this);

    connect( mMenuTree, SIGNAL(clicked(QModelIndex)), this, SLOT(clickMenu()));

    QFile qss(":/treewidget.qss");
    qss.open( QFile::ReadOnly );
    mMenuTree->setStyleSheet( qss.readAll() );
    qss.close();

    createActions();
    createStatusBar();
    createDockWindows();

    setWindowTitle( tr( "Content Help" ));
    setUnifiedTitleAndToolBarOnMac(true);

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());


}

ContentMain::~ContentMain()
{

}

void ContentMain::initialize()
{
    mMenuDock->setWindowTitle( tr("Information Menu") );
    mMenuDock->layout()->setSpacing(0);
    mMenuDock->layout()->setMargin(0);
}

void ContentMain::actSave()
{
    QTreeWidgetItem* item = mMenuTree->currentItem();
    if( item == NULL ) return;

    QString strName = item->text(0);
    QString strData = item->data(0, Qt::UserRole).toString();


    QStringList strList;

    strList = strData.split( "/" );
    if( strList.size() < 2 ) return;

    QString strType = strList.at(0);
    QString strPath;
    QString fileName;
    QString strSavePath;

    BIN binData = {0,0};

    if( strType == kRFC || strType == kPKIX )
    {
        if( strType == kRFC )
        {
            strSavePath = QString ( "%1/%2.html" ).arg( kDoc ).arg( strData );
            strPath = QString( "%1.html" ).arg( strData );
        }
        else
        {
            QStringList nameRFC = strData.split(":" );
            if( nameRFC.size() < 2 ) return;
            strSavePath = QString( "%1/%2/%3.html" ).arg( kDoc ).arg( kPKIX ).arg( nameRFC.at(1));
            strPath = QString( "%1.html" ).arg( nameRFC.at(1));
        }


        fileName = findSaveFile( this, JS_FILE_TYPE_ALL, strPath );
    }
    else
    {
        strSavePath = QString ( "%1/%2" ).arg( kDoc ).arg( strData );
        strPath = QString( "%1.asn1" ).arg( strData );
        fileName = findSaveFile( this, JS_FILE_TYPE_ALL, strPath );
    }

    if( fileName.length() < 1 ) return;

    JS_BIN_fileRead( strSavePath.toLocal8Bit().toStdString().c_str(), &binData );
    JS_BIN_fileWrite( &binData, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset( &binData );

    berApplet->messageBox( tr( "Save file(%1) successfully").arg( fileName), this );
}

void ContentMain::actPrint()
{
#if QT_CONFIG(printdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog *dlg = new QPrintDialog(&printer, this);

    if (mContentBroswer->textCursor().hasSelection())
#if QT_VERSION >= 0x060000
        dlg->setOptions(QAbstractPrintDialog::PrintSelection);
#else
        dlg->addEnabledOption(QAbstractPrintDialog::PrintSelection);
#endif

    dlg->setWindowTitle(tr("Print Document"));
    if (dlg->exec() == QDialog::Accepted)
    {
        QTextEdit txtEdit;
        QString strText = mContentBroswer->toPlainText();

        txtEdit.setText(strText);
        txtEdit.print(&printer);
    }
    delete dlg;
#endif
}

void ContentMain::actPrintPreview()
{
#if QT_CONFIG(printpreviewdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintPreviewDialog preview(&printer, this);
    connect(&preview, &QPrintPreviewDialog::paintRequested, this, &ContentMain::printPreview);
    preview.exec();
#endif
}

void ContentMain::actExpandAll()
{
    mMenuTree->expandAll();
}

void ContentMain::actExpandNode()
{
    QModelIndex index = mMenuTree->currentIndex();
    mMenuTree->expand( index );
}

void ContentMain::actCollapseAll()
{
    mMenuTree->collapseAll();
}

void ContentMain::actCollapseNode()
{
    QModelIndex index = mMenuTree->currentIndex();
    mMenuTree->collapse(index);
}

void ContentMain::actShowMenu()
{
    mMenuDock->show();
}

void ContentMain::actHideMenu()
{
    mMenuDock->hide();
}

void ContentMain::actQuit()
{
    close();
}

void ContentMain::printPreview(QPrinter *printer)
{
#ifdef QT_NO_PRINTER
    Q_UNUSED(printer);
#else
    QTextEdit txtEdit;
    QString strText = mContentBroswer->toPlainText();

    txtEdit.setText(strText);
    txtEdit.print(printer);
#endif
}

void ContentMain::createActions()
{
    connect( actionSave, &QAction::triggered, this, &ContentMain::actSave );
    connect( actionPrint, &QAction::triggered, this, &ContentMain::actPrint );
    connect( actionPrint_Preview, &QAction::triggered, this, &ContentMain::actPrintPreview);
    connect( actionExpand_All, &QAction::triggered, this, &ContentMain::actExpandAll );
    connect( actionExpand_Node, &QAction::triggered, this, &ContentMain::actExpandNode );
    connect( actionCollapse_All, &QAction::triggered, this, &ContentMain::actCollapseAll );
    connect( actionCollapse_Node, &QAction::triggered, this, &ContentMain::actCollapseNode );
    connect( actionShow_Menu, &QAction::triggered, this, &ContentMain::actShowMenu );
    connect( actionHide_Menu, &QAction::triggered, this, &ContentMain::actHideMenu );
    connect( actionQuit, &QAction::triggered, this, &ContentMain::actQuit );

    QToolBar *fileToolBar = addToolBar( tr("File" ));

    const QIcon saveIcon = QIcon::fromTheme("document-save", QIcon(":/images/save.png"));
    actionSave->setIcon( saveIcon );
    actionSave->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_1));
    fileToolBar->addAction( actionSave );

    const QIcon printIcon = QIcon::fromTheme("documet-print", QIcon(":/images/fileprint.png"));
    actionPrint->setIcon( printIcon );
    actionPrint->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_2));
    fileToolBar->addAction( actionPrint );

    actionPrint_Preview->setIcon( printIcon );
    actionPrint_Preview->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_3));

    QToolBar *editToolBar = addToolBar( tr( "Edit" ));

    const QIcon expandAllIcon = QIcon::fromTheme("expand-all", QIcon(":/images/expand_all.png"));
    actionExpand_All->setIcon( expandAllIcon );
    actionExpand_All->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_4));
    editToolBar->addAction( actionExpand_All );

    const QIcon expandNodeIcon = QIcon::fromTheme("expand-node", QIcon(":/images/expand_node.png"));
    actionExpand_Node->setIcon( expandNodeIcon );
    actionExpand_Node->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_5));
    editToolBar->addAction( actionExpand_Node );

    const QIcon collapseAllIcon = QIcon::fromTheme("collapse-all", QIcon(":/images/collapse_all.png"));
    actionCollapse_All->setIcon( collapseAllIcon );
    actionCollapse_All->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_6));
    editToolBar->addAction( actionCollapse_All );

    const QIcon collapseNodeIcon = QIcon::fromTheme("collapse-node", QIcon(":/images/collapse_node.png"));
    actionCollapse_Node->setIcon( collapseNodeIcon );
    actionCollapse_Node->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_7));
    editToolBar->addAction( actionCollapse_Node );

    const QIcon showMenuIcon = QIcon::fromTheme( "show-menu", QIcon(":/images/menu_show.png" ));
    actionShow_Menu->setIcon( showMenuIcon );
    actionShow_Menu->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_8));
    editToolBar->addAction( actionShow_Menu );

    const QIcon hideMenuIcon = QIcon::fromTheme( "hide-menu", QIcon(":/images/menu_hide.png"));
    actionHide_Menu->setIcon( hideMenuIcon );
    actionHide_Menu->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_9));
    editToolBar->addAction( actionHide_Menu );
}

void ContentMain::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void ContentMain::createDockWindows()
{
    mMenuTree->header()->setVisible(false);
    mMenuTree->clear();

    QDir dir;
    if( dir.exists( kDoc ) == false )
        dir.mkdir( kDoc );

    QTreeWidgetItem *rootItem = new QTreeWidgetItem;
    rootItem->setText( 0, "PKI Standard" );
    mMenuTree->insertTopLevelItem( 0, rootItem );

    QTreeWidgetItem *itemASN = new QTreeWidgetItem;
    itemASN->setText( 0, kASN1 );
    rootItem->addChild( itemASN );

    QString strASNPath = QString( "%1/%2" ).arg( kDoc ).arg( kASN1 );

    if( dir.exists( strASNPath ) == false )
        dir.mkdir( strASNPath );

    makeASNMenu( itemASN );

    QTreeWidgetItem *itemRFC = new QTreeWidgetItem;
    itemRFC->setText( 0, kRFC );
    rootItem->addChild( itemRFC );

    QString strRFCPath = QString( "%1/%2" ).arg( kDoc ).arg( kRFC );
    if( dir.exists( strRFCPath ) == false )
        dir.mkdir( strRFCPath );

    makeRFCMenu( itemRFC );

    QTreeWidgetItem *itemPKIX = new QTreeWidgetItem;
    itemPKIX->setText( 0, kPKIX );
    rootItem->addChild( itemPKIX );

    QString strPKIXPath = QString( "%1/%2" ).arg( kDoc ).arg( kPKIX );
    if( dir.exists( strPKIXPath ) == false )
        dir.mkdir( strPKIXPath );

    makePKIXMenu( itemPKIX );

    mMenuTree->expandAll();
}

void ContentMain::makeASNMenu( QTreeWidgetItem* parent )
{
    QStringList sASN1List = { "Implicit", "Explicit" };
    QString strPath = QString( "%1/%2" ).arg( kDoc ).arg( kASN1 );

    QDir dir( strPath );
    for( const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        if( file.isFile() == false )
            continue;

        if( file.completeSuffix().toLower() != "asn1" )
            continue;

        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strBase = file.baseName();
        QString strASN1 = file.fileName();
        QString strData = QString( "%1/%2" ).arg( kASN1 ).arg( strASN1 );

        item->setText( 0, strBase );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::makeRFCMenu( QTreeWidgetItem* parent )
{
    for( int i = 0; i < kRFCList.size(); i++ )
    {
        QString strRFC = kRFCList.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strData = QString( "%1/%2" ).arg( kRFC ).arg( strRFC );

        item->setText( 0, strRFC );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::makePKIXMenu( QTreeWidgetItem* parent )
{
    //QStringList sPKIXList = { "PKCS#1", "PKCS#3", "PKCS#5", "PKCS#7", "PKCS#8", "PKCS#10", "PKCS#11", "PKCS#12" };
    // PKCS#1 : RFC8017
    // PKCS#3 : RFC2631
    // PKCS#5 : RFC2898
    // PKCS#7 : RFC5652
    // PKCS#8 : RFC5208
    // PKCS#9 : RFC2985
    // PKCS#10 : RFC2986
    // PKCS#11
    // PKCS#12 : RFC7292

    for( int i = 0; i < kPKIXList.size(); i++ )
    {
        QString strPKIX = kPKIXList.at(i);
        QStringList nameRFC = strPKIX.split(":");

        if( nameRFC.size() < 2 ) continue;

        QString strName = nameRFC.at(0);

        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strData = QString( "%1/%2" ).arg( kPKIX ).arg( strPKIX );

        item->setText( 0, strName );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::clickMenu()
{
    int ret = 0;
    mContentBroswer->clear();

//    QString strURL = "https://www.naver.com";
    QTreeWidgetItem* item = mMenuTree->currentItem();
    if( item == NULL ) return;

    QString strName = item->text(0);
    QString strData = item->data(0, Qt::UserRole).toString();

    QStringList strList;

    strList = strData.split( "/" );
    if( strList.size() < 2 ) return;

    QString strType = strList.at(0);

    if( strType == kRFC || strType == kPKIX )
    {
        int nStatus = 0;
        char *pBody = NULL;
        BIN binBody = {0,0};
        QString strURL;
        QString strSavePath;

        if( strType == kRFC )
        {
            strURL = QString( "%1/%2.html").arg( kRFCHost ).arg( strName ).toLower();
            strSavePath = QString ( "%1/%2.html" ).arg( kDoc ).arg( strData );
        }
        else
        {
            QStringList nameRFC = strData.split(":" );
            if( nameRFC.size() < 2 ) return;

            strURL = QString( "%1/%2.html" ).arg( kPKIXHost ).arg( nameRFC.at(1) ).toLower();
            strSavePath = QString( "%1/%2/%3.html" ).arg( kDoc ).arg( kPKIX ).arg( nameRFC.at(1));
        }

        QFileInfo fileInfo( strSavePath );
        if( fileInfo.exists() == true )
        {
//            QString fileName = "D:/mywork/QtHelpManual/documentation/index.html";  // 표시할 HTML 파일 경로
            QFile file( strSavePath );
            if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                berApplet->warningBox( tr( "fail to open HTML" ), this );
                return;
            }

            // 파일 내용 읽기
            QTextStream in(&file);
            QString htmlContent = in.readAll();
            file.close();
            mContentBroswer->setHtml( htmlContent );
        }
        else
        {
            ret = JS_HTTP_requestGetBin2( strURL.toStdString().c_str(), NULL, NULL, &nStatus, &binBody );

            JS_BIN_string( &binBody, &pBody );
            mContentBroswer->setHtml( pBody );
            JS_BIN_fileWrite( &binBody, strSavePath.toLocal8Bit().toStdString().c_str() );


            if( pBody ) JS_free( pBody );
            JS_BIN_reset( &binBody );

        }
    }
    else
    {
        QString strSavePath = QString ( "%1/%2" ).arg( kDoc ).arg( strData );
        QFileInfo fileInfo( strSavePath );

        if( fileInfo.exists() == true )
        {
            QFile file( strSavePath );
            if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                berApplet->warningBox( tr( "fail to open HTML" ), this );
                return;
            }

            // 파일 내용 읽기
            QTextStream in(&file);
            QString textContent = in.readAll();
            file.close();
            mContentBroswer->setPlainText( textContent );
        }
        else
        {
            mContentBroswer->setPlainText( "There is no data" );
        }
    }
}
