#include "x509_compare_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"

#include "js_pki.h"

X509CompareDlg::X509CompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAFindBtn, SIGNAL(clicked()), this, SLOT(clickAFind()));
    connect( mBFindBtn, SIGNAL(clicked()), this, SLOT(clickBFind()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mCompareBtn, SIGNAL(clicked()), this, SLOT(clickCompare()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

X509CompareDlg::~X509CompareDlg()
{

}

void X509CompareDlg::initUI()
{
    QStringList sTypeList = { tr("Certificate" ), tr( "CRL" ), tr( "CSR" ) };
    QStringList sBaseLabels = { tr("Field"), tr("A Value"), tr( "B Value" ), tr( "O|X") };

    mCompareTable->clear();
    mCompareTable->horizontalHeader()->setStretchLastSection(true);
    mCompareTable->setColumnCount(sBaseLabels.size());
    mCompareTable->setHorizontalHeaderLabels( sBaseLabels );
    mCompareTable->verticalHeader()->setVisible(false);
    mCompareTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCompareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCompareTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mTypeCombo->addItems( sTypeList );
}


void X509CompareDlg::initialize()
{

}

void X509CompareDlg::clickAFind()
{
    QString strPath = mAPathText->text();

    QString strFilePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFilePath.length() > 0 )
    {
        mAPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickBFind()
{
    QString strPath = mBPathText->text();

    QString strFilePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFilePath.length() > 0 )
    {
        mBPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickClear()
{
    mCompareTable->setRowCount(0);
}

void X509CompareDlg::clickCompare()
{

}
