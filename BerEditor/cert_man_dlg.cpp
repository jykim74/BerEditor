#include "cert_man_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"

CertManDlg::CertManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

    initUI();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

CertManDlg::~CertManDlg()
{

}

void CertManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CertManDlg::initUI()
{
    QStringList sTableLabels = { tr( "Subject DN" ), tr( "Expire" ), tr( "Issuer DN" ) };

    mEE_CertTable->clear();
    mEE_CertTable->horizontalHeader()->setStretchLastSection(true);
    mEE_CertTable->setColumnCount( sTableLabels.size() );
    mEE_CertTable->setHorizontalHeaderLabels( sTableLabels );
    mEE_CertTable->verticalHeader()->setVisible(false);
    mEE_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mEE_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mEE_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCA_CertTable->clear();
    mCA_CertTable->horizontalHeader()->setStretchLastSection(true);
    mCA_CertTable->setColumnCount( sTableLabels.size() );
    mCA_CertTable->setHorizontalHeaderLabels( sTableLabels );
    mCA_CertTable->verticalHeader()->setVisible(false);
    mCA_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCA_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCA_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void CertManDlg::initialize()
{

}
