#include <QFileInfo>
#include <QTextStream>
#include <QDir>

#include <QtHelp/QHelpEngine>
#include "content_main.h"
#include "common.h"
#include "ber_applet.h"
#include "js_http.h"

static const QString kDoc = "DOC";
static const QString kRFC = "RFC";
static const QString kASN1 = "ASN1";
static const QString kPKIX = "PKIX";

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
}

void ContentMain::makeASNMenu( QTreeWidgetItem* parent )
{
    QStringList sASN1List = { "Implicit", "Explicit" };

    for( int i = 0; i < sASN1List.size(); i++ )
    {
        QString strASN1 = sASN1List.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strData = QString( "%1/%2" ).arg( kASN1 ).arg( strASN1 );

        item->setText( 0, strASN1 );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::makeRFCMenu( QTreeWidgetItem* parent )
{
    QStringList sRFCList = { "RFC5280", "RFC4210", "RFC4211", "RFC2560", "RFC3161", "RFC8894" };

    for( int i = 0; i < sRFCList.size(); i++ )
    {
        QString strRFC = sRFCList.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strData = QString( "%1/%2" ).arg( kRFC ).arg( strRFC );

        item->setText( 0, strRFC );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::makePKIXMenu( QTreeWidgetItem* parent )
{
    QStringList sPKIXList = { "PKCS#1", "PKCS#3", "PKCS#5", "PKCS#7", "PKCS#8", "PKCS#9", "PKCS#10", "PKCS#11", "PKCS#12" };
    // PKCS#1 : RFC2437
    // PKCS#3 : RFC2631
    // PKCS#5 : RFC2898
    // PKCS#7 : RFC2315
    // PKCS#8 : RFC5208
    // PKCS#9 : RFC2985
    // PKCS#10 : RFC2986
    // PKCS#11
    // PKCS#12 : RFC7292

    for( int i = 0; i < sPKIXList.size(); i++ )
    {
        QString strPKIX = sPKIXList.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem;
        QString strData = QString( "%1/%2" ).arg( kPKIX ).arg( strPKIX );

        item->setText( 0, strPKIX );
        item->setData( 0, Qt::UserRole, strData );
        parent->addChild( item );
    }
}

void ContentMain::clickMenu()
{
    int ret = 0;

//    QString strURL = "https://www.naver.com";
    QTreeWidgetItem* item = mMenuTree->currentItem();
    if( item == NULL ) return;

    QString strName = item->text(0);
    QString strData = item->data(0, Qt::UserRole).toString();

    QStringList strList;

    strList = strData.split( "/" );
    if( strList.size() < 2 ) return;

    QString strType = strList.at(0);

    if( strType == kRFC )
    {
        int nStatus = 0;
        char *pBody = NULL;
        BIN binBody = {0,0};
        QString strHost = "https://www.rfc-editor.org/rfc/inline-errata";

        QString strURL = QString( "%1/%2.html").arg( strHost ).arg( strName ).toLower();
        QString strSavePath = QString ( "%1/%2.html" ).arg( kDoc ).arg( strData );

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
        QString strSavePath = QString ( "%1/%2.html" ).arg( kDoc ).arg( strData );
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
