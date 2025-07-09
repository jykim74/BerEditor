#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <qmenu.h>

#include "acme_tree_dlg.h"
#include "js_bin.h"

ACMETreeDlg::ACMETreeDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mMsgTree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), this, SLOT(clickTreeItem(QTreeWidgetItem*,int)));
    connect( mMsgTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
}

ACMETreeDlg::~ACMETreeDlg()
{

}

void ACMETreeDlg::initUI()
{
    mMsgTree->clear();
    mMsgTree->header()->setVisible( false );
    mMsgTree->setColumnCount(1);
}

void ACMETreeDlg::setObject( QTreeWidgetItem* pParentItem, QJsonObject& object )
{
    int nCount = object.count();
    QStringList listKeys = object.keys();

    for( int i = 0; i < nCount; i++ )
    {
        QTreeWidgetItem* pItem = new QTreeWidgetItem;
        QString strKey = listKeys.at(i);
        pItem->setData( 0, 100, object[strKey].type() );

        if( object[strKey].isString() == true )
        {
            QString strValue = object[strKey].toString();
            pItem->setText( 0, QString( "%1 : \"%2\"").arg( strKey ).arg( strValue ) );
            pItem->setData( 0, Qt::UserRole, strValue );
            pItem->setIcon( 0, QIcon(":/images/circle.png" ));
        }
        else if( object[strKey].isArray() == true )
        {
            QJsonArray jArr = object[strKey].toArray();
            pItem->setText( 0, QString( "[] %1").arg( strKey ) );
            setArray( pItem, jArr );
        }
        else if( object[strKey].isObject() == true )
        {
            QJsonObject jObj = object[strKey].toObject();

            pItem->setText( 0, QString( "{} %1").arg( strKey ) );
            setObject( pItem, jObj );
        }
        else if( object[strKey].isBool() == true )
        {
            bool bVal = object[strKey].toBool();
            pItem->setText( 0, QString( "%1 : %2").arg( strKey ).arg( bVal ? "true" : "false" ) );
            pItem->setData( 0, Qt::UserRole, bVal );
            pItem->setIcon( 0, QIcon(":/images/bool.png" ));
        }
        else
        {
            int nVal = object[strKey].toInt();
            pItem->setText( 0, QString( "%1 : %2").arg( strKey ).arg( nVal ) );
            pItem->setData( 0, Qt::UserRole, nVal );
            pItem->setIcon( 0, QIcon(":/images/nemo.png" ));
        }

        pParentItem->addChild( pItem );
    }
}

void ACMETreeDlg::setArray( QTreeWidgetItem* pParentItem, QJsonArray& array )
{
    int nCount = array.count();

    for( int i = 0; i < nCount; i++ )
    {
        QTreeWidgetItem* pItem = new QTreeWidgetItem;
        QJsonValue jVal = array.at(i);
        pItem->setData( 0, 100, jVal.type() );

        if( jVal.isString() == true )
        {
            QString strValue = jVal.toString();
            pItem->setText( 0, QString( "\"%1\"").arg( strValue ) );
            pItem->setData( 0, Qt::UserRole, strValue );
            pItem->setIcon( 0, QIcon(":/images/circle.png" ));
        }
        else if( jVal.isArray() == true )
        {
            QJsonArray jArr = jVal.toArray();
            pItem->setText( 0, QString( "[]") );
            setArray( pItem, jArr );
        }
        else if( jVal.isObject() == true )
        {
            QJsonObject jObj = jVal.toObject();

            pItem->setText( 0, QString( "{}") );
            setObject( pItem, jObj );
        }
        else if( jVal.isBool() == true )
        {
            bool bVal = jVal.toBool();
            pItem->setText( 0, QString( "%1").arg( bVal ? "true" : "false") );
            pItem->setData( 0, Qt::UserRole, bVal );
            pItem->setIcon( 0, QIcon(":/images/bool.png" ));
        }
        else
        {
            int nVal = jVal.toInt();
            pItem->setText( 0, QString( "%1").arg( nVal ) );
            pItem->setData( 0, Qt::UserRole, nVal );
            pItem->setIcon( 0, QIcon(":/images/nemo.png" ));
        }

        pParentItem->addChild( pItem );
    }
}

void ACMETreeDlg::setJson( const QString strJson )
{
    QJsonDocument jsonDoc;
    jsonDoc = QJsonDocument::fromJson( strJson.toLocal8Bit() );
    json_ = jsonDoc.object();

    QTreeWidgetItem *pRoot = new QTreeWidgetItem;
    pRoot->setText( 0, "{} JSON" );
    setObject( pRoot, json_ );

    mMsgTree->insertTopLevelItem(0, pRoot);
    mMsgTree->expandAll();
}

void ACMETreeDlg::clickTreeItem( QTreeWidgetItem* item, int index )
{
    if( item == NULL ) return;

    QString strValue = item->data(0, Qt::UserRole).toString();
    mMsgText->setPlainText( strValue );
}

void ACMETreeDlg::slotTreeMenuRequested( QPoint pos )
{
    QTreeWidgetItem* item = mMsgTree->currentItem();
    if( item == NULL ) return;

    if( item->data(0, 100) != QJsonValue::String )
        return;

    QMenu *menu = new QMenu(this);
    QAction *decodeAct = new QAction( tr( "Decode"), this);

    connect( decodeAct, SIGNAL(triggered()), this, SLOT(decodeTreeMenu()));
    menu->addAction( decodeAct );
    menu->popup( mMsgTree->viewport()->mapToGlobal(pos));
}

void ACMETreeDlg::clickClear()
{
    mMsgText->clear();
}

void ACMETreeDlg::decodeTreeMenu()
{
    QTreeWidgetItem* item = mMsgTree->currentItem();
    if( item == NULL ) return;

    BIN binData = {0,0};
    int nType = item->data(0, 100).toInt();

    if( nType == QJsonValue::String )
    {
        char *pValue = NULL;
        QString strValue = item->data(0, Qt::UserRole ).toString();
        JS_BIN_decodeBase64URL( strValue.toStdString().c_str(), &binData );
        JS_BIN_string( &binData, &pValue );

        QJsonDocument jDoc = QJsonDocument::fromJson( pValue );

        if( jDoc.isArray() )
        {
            QJsonArray jArr = jDoc.array();
            setArray( item, jArr );
        }
        else if( jDoc.isObject() )
        {
            QJsonObject jObj = jDoc.object();
            setObject( item, jObj );
        }
    }

    mMsgTree->expandItem( item );
    JS_BIN_reset( &binData );
}
