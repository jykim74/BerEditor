#include "x509_compare_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"

#include "js_pki.h"
#include "js_pki_x509.h"

X509CompareDlg::X509CompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    memset( &A_bin_, 0x00, sizeof(BIN));
    memset( &B_bin_, 0x00, sizeof(BIN));

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
    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );
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
    int ret = 0;

    JCertInfo ACertInfo;
    JCertInfo BCertInfo;

    JCRLInfo ACRLInfo;
    JCRLInfo BCRLInfo;

    JReqInfo AReqInfo;
    JReqInfo BReqInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    QString strAPath = mAPathText->text();
    QString strBPath = mBPathText->text();

    if( strAPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a A file" ), this );
        return;
    }

    if( strBPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a B file" ), this );
        return;
    }

    memset( &ACertInfo, 0x00, sizeof(JCertInfo));
    memset( &BCertInfo, 0x00, sizeof(JCertInfo));

    memset( &ACRLInfo, 0x00, sizeof(JCRLInfo));
    memset( &BCRLInfo, 0x00, sizeof(JCRLInfo));

    memset( &AReqInfo, 0x00, sizeof(JReqInfo));
    memset( &BReqInfo, 0x00, sizeof(JReqInfo));


    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );

    JS_BIN_fileReadBER( strAPath.toLocal8Bit().toStdString().c_str(), &A_bin_ );
    JS_BIN_fileReadBER( strBPath.toLocal8Bit().toStdString().c_str(), &B_bin_ );

    if( mTypeCombo->currentIndex() == 0 ) // Certificate
    {
        ret = JS_PKI_getCertInfo( &A_bin_, &ACertInfo, &pAExtList );
        if( ret != 0 )
        {
            goto end;
        }

        ret = JS_PKI_getCertInfo( &B_bin_, &BCertInfo, &pBExtList );
        if( ret != 0 )
        {
            goto end;
        }
    }
    else if( mTypeCombo->currentIndex() == 1 ) // CRL
    {
        ret = JS_PKI_getCRLInfo( &A_bin_, &ACRLInfo, &pAExtList, NULL );
        if( ret != 0 )
        {
            goto end;
        }

        ret = JS_PKI_getCRLInfo( &B_bin_, &BCRLInfo, &pBExtList, NULL );
        if( ret != 0 )
        {
            goto end;
        }
    }
    else if( mTypeCombo->currentIndex() == 2 ) // CSR
    {
        ret = JS_PKI_getReqInfo( &A_bin_, &AReqInfo, 0, &pAExtList );
        if( ret != 0 )
        {
            goto end;
        }

        ret = JS_PKI_getReqInfo( &B_bin_, &BReqInfo, 0, &pBExtList );
        if( ret != 0 )
        {
            goto end;
        }
    }

end :

}
