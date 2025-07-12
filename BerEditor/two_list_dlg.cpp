#include "two_list_dlg.h"
#include "common.h"
#include "ber_applet.h"

TwoListDlg::TwoListDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TwoListDlg::~TwoListDlg()
{

}

void TwoListDlg::initUI()
{
    QStringList sTableLabels = { "Name", "Name2" };

    mNameTable->clear();
    mNameTable->horizontalHeader()->setStretchLastSection(true);
    mNameTable->setColumnCount( sTableLabels.size() );
    mNameTable->setHorizontalHeaderLabels( sTableLabels );
    mNameTable->verticalHeader()->setVisible(false);
    mNameTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mNameTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mNameTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void TwoListDlg::setNames( const QString strName, const QString strName2 )
{
    mNameTable->setRowCount(0);

    QTableWidgetItem *item = mNameTable->horizontalHeaderItem(0);
    QTableWidgetItem *item2 = mNameTable->horizontalHeaderItem(1);

    item->setText( strName );
    item2->setText( strName2 );

    mNameLabel->setText( strName );
    mName2Label->setText( strName2 );
}

void TwoListDlg::clickAdd()
{
    QString strName = mNameText->text();
    QString strLabel = mNameLabel->text();

    QString strName2 = mName2Text->text();
    QString strLabel2 = mName2Label->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a %1").arg( strLabel), this );
        mNameText->setFocus();
        return;
    }

    if( strName2.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a %1").arg( strLabel2), this );
        mName2Text->setFocus();
        return;
    }
}

void TwoListDlg::clickOK()
{
    accept();
}

void TwoListDlg::clickClear()
{
    mNameTable->setRowCount(0);
}
