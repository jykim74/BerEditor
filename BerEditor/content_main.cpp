#include <QFileInfo>
#include <QTextStream>

#include <QtHelp/QHelpEngine>
#include "content_main.h"
#include "common.h"
#include "ber_applet.h"
#include "js_http.h"

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
    int ret = 0;
    int nStatus = 0;
    char *pBody = NULL;
    BIN binBody = {0,0};
    QString strURL = "https://www.rfc-editor.org/rfc/inline-errata/rfc5280.html";
//    QString strURL = "https://www.naver.com";
    QTreeWidgetItem* item = mMenuTree->currentItem();

    if( item == NULL ) return;

    ret = JS_HTTP_requestGetBin2( strURL.toStdString().c_str(), NULL, NULL, &nStatus, &binBody );
/*
    // HTML 파일 읽기

    QString fileName = "D:/mywork/QtHelpManual/documentation/index.html";  // 표시할 HTML 파일 경로
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        berApplet->warningBox( tr( "fail to open HTML" ), this );
        return;
    }

    // 파일 내용 읽기
    QTextStream in(&file);
    QString htmlContent = in.readAll();
    file.close();
*/
    JS_BIN_string( &binBody, &pBody );
    mContentBroswer->setHtml( pBody );
    if( pBody ) JS_free( pBody );
    JS_BIN_reset( &binBody );
//    mContentBroswer->setPlainText( htmlContent );
}
