#include <QDir>
#include <QFileInfo>

#include "link_man_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h"

LinkManDlg::LinkManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mRemoveBtn, SIGNAL(clicked()), this, SLOT(clickRemove()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    mURIText->setFocus();
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

LinkManDlg::~LinkManDlg()
{

}

void LinkManDlg::initialize()
{
    int row = 0;
    QStringList sLinkFields = { tr( "Name" ), tr( "URI" ) };

    mLinkTable->clear();
    mLinkTable->horizontalHeader()->setStretchLastSection( true );
    mLinkTable->setColumnCount( sLinkFields.size() );
    mLinkTable->setHorizontalHeaderLabels( sLinkFields );
    mLinkTable->verticalHeader()->setVisible(false);
    mLinkTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mLinkTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mLinkTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QString strLinks = berApplet->settingsMgr()->linkList();

    QStringList listLink = strLinks.split( "\n" );
    for( int i = 0; i < listLink.size(); i++ )
    {
        QString strNameURI = listLink.at(i);
        QStringList nameVal = strNameURI.split( "##" );
        if( nameVal.size() < 2 ) continue;

        QString strName = nameVal.at(0);
        QString strURI = nameVal.at(1);

        mLinkTable->insertRow(row);
        mLinkTable->setRowHeight(row, 10);
        mLinkTable->setItem( row, 0, new QTableWidgetItem( QString("%1").arg( strName )));
        mLinkTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( strURI )));

        row++;
    }
}

void LinkManDlg::clickAdd()
{
    QString strURI = mURIText->text();
    QString strName = mNameText->text();

    if( strURI.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a URI" ), this );
        mURIText->setFocus();
        return;
    }

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    if( isHTTP( strURI ) == false )
    {
        berApplet->warningBox( tr( "URI is not http link" ), this );
        mURIText->setFocus();
        return;
    }

    int row = mLinkTable->rowCount();
    mLinkTable->insertRow(row);
    mLinkTable->setRowHeight(row, 10);
    mLinkTable->setItem( row, 0, new QTableWidgetItem( QString("%1").arg( strName ).simplified()));
    mLinkTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( strURI ).simplified()));

    mURIText->clear();
    mNameText->clear();
}

void LinkManDlg::clickRemove()
{
    int row = mLinkTable->currentRow();
    if( row < 0 )
    {
        berApplet->warningBox( tr( "Select URI" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure to remove?" ), this, true );
    if( bVal == false ) return;

    mLinkTable->removeRow(row);
}

void LinkManDlg::clickClearAll()
{
    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure to clear all?" ), this, true );
    if( bVal == false ) return;

    mLinkTable->setRowCount(0);
}

void LinkManDlg::clickOK()
{
    QString strLinkList;
    int rowCount = mLinkTable->rowCount();

    for( int i = 0; i < rowCount; i++ )
    {
        QTableWidgetItem *item0 = mLinkTable->item( i, 0 );
        QTableWidgetItem* item1 = mLinkTable->item( i, 1 );

        if( item0 == NULL || item1 == NULL ) return;

        QString strLink = QString( "%1##%2\n" ).arg( item0->text() ).arg( item1->text() );
        strLinkList += strLink;
    }

    berApplet->settingsMgr()->setLinkList( strLinkList );
    accept();
}
