#include "cms_info_dlg.h"
#include "ber_applet.h"

#include "js_pki.h"
#include "js_pkcs7.h"
#include "js_util.h"

#include "common.h"

CMSInfoDlg::CMSInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    memset( &cms_bin_, 0x00, sizeof(BIN));

    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCertCRLTab->layout()->setSpacing(5);
    mCertCRLTab->layout()->setMargin(5);

    mSignerRecipTab->layout()->setSpacing(5);
    mSignerRecipTab->layout()->setMargin(5);
#endif
    initUI();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CMSInfoDlg::~CMSInfoDlg()
{
    JS_BIN_reset( &cms_bin_ );
}

void CMSInfoDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif

    QStringList sTableLabels = { tr( "Subject DN" ), tr( "Expire" ), tr( "Issuer DN" ) };

    mCertTable->clear();
    mCertTable->horizontalHeader()->setStretchLastSection(true);
    mCertTable->setColumnCount( sTableLabels.size() );
    mCertTable->setHorizontalHeaderLabels( sTableLabels );
    mCertTable->verticalHeader()->setVisible(false);
    mCertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCertTable->setColumnWidth( 0, nWidth * 5/10 );
    mCertTable->setColumnWidth( 1, nWidth * 2/10 );
    mCertTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sCRLTableLabels = { tr( "Issuer DN" ), tr( "This Update"), tr( "Next Update" ) };

    mCRLTable->clear();
    mCRLTable->horizontalHeader()->setStretchLastSection(true);
    mCRLTable->setColumnCount( sCRLTableLabels.size() );
    mCRLTable->setHorizontalHeaderLabels( sCRLTableLabels );
    mCRLTable->verticalHeader()->setVisible(false);
    mCRLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCRLTable->setColumnWidth( 0, nWidth * 6/10 );
    mCRLTable->setColumnWidth( 1, nWidth * 2/10 );
    mCRLTable->setColumnWidth( 2, nWidth * 2/10 );
}

void CMSInfoDlg::setCMS( const BIN *pCMS )
{
    QString strType;
    cms_type_ = JS_PKCS7_getType( pCMS );

    JS_BIN_reset( &cms_bin_ );
    JS_BIN_copy( &cms_bin_, pCMS );

    if( cms_type_ == JS_PKCS7_TYPE_SIGNED )
    {
        setSigned();
        strType = "Signed";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_ENVELOED )
    {
        setEnveloped();
        strType = "Enveloped";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_SIGNED_AND_ENVELOPED )
    {
        setSignedAndEnveloped();
        strType = "SignedAndEnveloped";
    }
    else
    {
        berApplet->warningBox( tr( "This type is not supported." ).arg( cms_type_ ), this );
    }

    mTypeText->setText( strType );
}

void CMSInfoDlg::dataChanged()
{
    QString strData = mDataText->toPlainText();

    QString strLen = getDataLenString( DATA_HEX, strData );
    mDataLenText->setText( QString("%1").arg( strLen ));
}

void CMSInfoDlg::setSigned()
{
    int ret = 0;
    int row = 0;
    JSignedData sSignedData;
    JSignerInfoList *pInfoList = NULL;
    time_t now = time(NULL);

    memset( &sSignedData, 0x00, sizeof(sSignedData));

    ret = JS_PKCS7_getSignedData( &cms_bin_, &sSignedData, &pInfoList );

    mVersionText->setText( QString("%1").arg( sSignedData.nVersion ));
    mDataText->setPlainText( getHexString( &sSignedData.binContent ));

    if( sSignedData.nMDCnt > 0 )
    {
        QString strAlg;
        JStrList *pCurList = sSignedData.pMDList;

        while( pCurList )
        {
            if( strAlg.length() < 1 )
                strAlg = pCurList->pStr;
            else
                strAlg = QString( ";%1" ).arg( pCurList->pStr );

            pCurList = pCurList->pNext;
        }

    //    mDigestAlgText->setText( strAlg );
    }

    for( int i = 0; i < sSignedData.nCertCnt; i++ )
    {
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        ret = JS_PKI_getCertInfo( &sSignedData.pCertList[i], &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

        mCertTable->insertRow( row );
        mCertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        mCertTable->setItem( row, 0, item );
        mCertTable->setItem( row, 1, new QTableWidgetItem( sNotAfter ));
        mCertTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_PKI_resetCertInfo( &sCertInfo );
    }

    for( int i = 0; i < sSignedData.nCRLCnt; i++ )
    {
        JCRLInfo sCRLInfo;

        char    sThisUpdate[64];
        char    sNextUpdate[64];

        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        ret = JS_PKI_getCRLInfo( &sSignedData.pCRLList[i], &sCRLInfo, NULL, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCRLInfo.uThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.uNextUpdate, sNextUpdate );

        mCRLTable->insertRow( row );
        mCRLTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.uNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        mCRLTable->setItem( row, 0, item );
        mCRLTable->setItem( row, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( row, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    JS_PKCS7_resetSignedData( &sSignedData );
    if( pInfoList ) JS_PKCS7_resetSignerInfoList( &pInfoList );
}

void CMSInfoDlg::setEnveloped()
{

}

void CMSInfoDlg::setSignedAndEnveloped()
{

}
