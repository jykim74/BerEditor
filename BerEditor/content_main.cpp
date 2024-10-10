#include <QtHelp/QHelpEngine>
#include "content_main.h"

ContentMain::ContentMain(QWidget *parent) :
    QMainWindow(parent)
{
    setupUi(this);

    connect( mMenuTree, SIGNAL(clicked(QModelIndex)), this, SLOT(clickMenu()));

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

void ContentMain::createActions()
{

}

void ContentMain::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void ContentMain::createDockWindows()
{

    mMenuTree->header()->setVisible(false);
    mMenuTree->clear();

    QTreeWidgetItem *rootItem = new QTreeWidgetItem;
    rootItem->setText( 0, "PKI Standard" );
    mMenuTree->insertTopLevelItem( 0, rootItem );

    QTreeWidgetItem *itemASN = new QTreeWidgetItem;
    itemASN->setText( 0, "ASN.1" );
    rootItem->addChild( itemASN );

    QTreeWidgetItem *itemRFC = new QTreeWidgetItem;
    itemRFC->setText( 0, "RFC" );
    rootItem->addChild( itemRFC );

    QTreeWidgetItem *itemPKIX = new QTreeWidgetItem;
    itemPKIX->setText( 0, "PKIX" );
    rootItem->addChild( itemPKIX );
}

void ContentMain::clickMenu()
{
    QTreeWidgetItem* item = mMenuTree->currentItem();

    if( item == NULL ) return;

    QString strName = item->text(0);
    QUrl url;
    url.setHost( "https://www.google.com" );

//    mContentBroswer->loadResource( QTextDocument::HtmlResource, url );
    mContentBroswer->setPlainText( strName );
}
