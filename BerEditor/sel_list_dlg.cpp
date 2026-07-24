#include "sel_list_dlg.h"
#include "common.h"

SelListDlg::SelListDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

SelListDlg::~SelListDlg()
{

}

void SelListDlg::setHeadLabel( const QString strLabel )
{
    mHeadLabel->setText( strLabel );
}

void SelListDlg::initUI()
{
    QStringList sBaseLabels = { tr("Type"), tr( "URL" ) };

    mListTable->clear();
    mListTable->horizontalHeader()->setStretchLastSection(true);
    mListTable->setColumnCount(sBaseLabels.size());
    mListTable->setHorizontalHeaderLabels( sBaseLabels );
    mListTable->verticalHeader()->setVisible(false);
    mListTable->setStyleSheet( kSelectStyle );
    mListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mListTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mListTable->setColumnWidth( 0, 100 );
}

void SelListDlg::initialize()
{

}

void SelListDlg::clickOK()
{
    type_.clear();
    url_.clear();

    QModelIndex idx = mListTable->currentIndex();
    QTableWidgetItem* item = mListTable->item( idx.row(), 0 );
    QTableWidgetItem* item1 = mListTable->item( idx.row(), 1 );

    if( item == NULL || item1 == NULL ) return;

    type_ = item->text();
    url_ = item1->text();

    accept();
}

void SelListDlg::addList( const QString strType, const QString strURL )
{
    QTableWidgetItem* item1 = new QTableWidgetItem( strURL );
    item1->setToolTip( strURL );

    mListTable->insertRow(0);
    mListTable->setRowHeight(0,10);
    mListTable->setItem(0, 0, new QTableWidgetItem( strType ));
    mListTable->setItem(0, 1, item1 );
}

void SelListDlg::selectURL( const QString strURL )
{
    int nCount = mListTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item = mListTable->item( i, 0 );
        QTableWidgetItem *item1 = mListTable->item( i, 1 );

        if( item1->text() == strURL )
        {
//            item->setSelected( true );
//            item1->setSelected( true );
            mListTable->setCurrentItem( item1 );
            break;
        }
    }
}

const QString SelListDlg::getURL()
{
    QString strURL = url_;

    return strURL;
}
