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
    QStringList sDataLabels = { tr("Name"), tr("Value") };
    mDataTable->clear();
    mDataTable->horizontalHeader()->setStretchLastSection(true);
    mDataTable->setColumnCount( sDataLabels.size() );
    mDataTable->setHorizontalHeaderLabels( sDataLabels );
    mDataTable->verticalHeader()->setVisible(false);
    mDataTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mDataTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mDataTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mDataTable->setColumnWidth( 0, nWidth * 5/10 );

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

    mSignerTable->clear();
    mSignerTable->horizontalHeader()->setStretchLastSection(true);
    mSignerTable->setColumnCount( sDataLabels.size() );
    mSignerTable->setHorizontalHeaderLabels( sDataLabels );
    mSignerTable->verticalHeader()->setVisible(false);
    mSignerTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mSignerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mSignerTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mSignerTable->setColumnWidth( 0, nWidth * 5/10 );

    mRecipTable->clear();
    mRecipTable->horizontalHeader()->setStretchLastSection(true);
    mRecipTable->setColumnCount( sDataLabels.size() );
    mRecipTable->setHorizontalHeaderLabels( sDataLabels );
    mRecipTable->verticalHeader()->setVisible(false);
    mRecipTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRecipTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRecipTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mRecipTable->setColumnWidth( 0, nWidth * 5/10 );
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
    JSignerInfoList *pCurList = NULL;
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
        mDataTable->insertRow(row);
        mDataTable->setItem( row, 0, new QTableWidgetItem("Digest Alg"));
        mDataTable->setItem( row, 1, new QTableWidgetItem( strAlg));
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

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        mCertTable->setItem( i, 0, item );
        mCertTable->setItem( i, 1, new QTableWidgetItem( sNotAfter ));
        mCertTable->setItem( i, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

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

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.uNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    pCurList = pInfoList;

    while( pCurList )
    {
        int idx = 0;
        mSignerTable->insertRow(idx);
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Version"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.nVersion )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Issuer"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pIssuer )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Serial"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pSerial )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("DigestAlg"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pDigestAlg )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("DigestEncAlg"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pDigestEncAlg )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("EncDigest"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pEncDigest )));

        if( pCurList->sSignerInfo.pAuthAttr )
        {
            JNumValList *pCurValList = pCurList->sSignerInfo.pAuthAttr;

            while( pCurValList )
            {
                mSignerTable->insertRow( ++idx );
                mSignerTable->setItem( idx, 0, new QTableWidgetItem("AuthAttr"));
                mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                pCurValList = pCurValList->pNext;
            }
        }

        if( pCurList->sSignerInfo.pUnauthAttr )
        {
            JNumValList *pCurValList = pCurList->sSignerInfo.pUnauthAttr;

            while( pCurValList )
            {
                mSignerTable->insertRow( ++idx );
                mSignerTable->setItem( idx, 0, new QTableWidgetItem("UnauthAttr"));
                mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                pCurValList = pCurValList->pNext;
            }
        }

        pCurList = pCurList->pNext;
    }

    JS_PKCS7_resetSignedData( &sSignedData );
    if( pInfoList ) JS_PKCS7_resetSignerInfoList( &pInfoList );
}

void CMSInfoDlg::setEnveloped()
{
    int ret = 0;
    int row = 0;
    JEnvelopedData sEnvelopedData;
    JRecipInfoList *pInfoList = NULL;
    JRecipInfoList *pCurList = NULL;

    memset( &sEnvelopedData, 0x00, sizeof(sEnvelopedData));

    ret = JS_PKCS7_getEnvelopedData( &cms_bin_, &sEnvelopedData, &pInfoList );

    mVersionText->setText( QString("%1").arg( sEnvelopedData.nVersion ));
    mDataText->setPlainText( getHexString( &sEnvelopedData.binEncData ));

    mDataTable->insertRow(row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("ContentType"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pContentType ));

    mDataTable->insertRow(++row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pAlg ));

    mDataTable->insertRow(++row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Cipher"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pCipher ));

    pCurList = pInfoList;

    while( pCurList )
    {
        int idx = 0;
        mRecipTable->insertRow(idx);
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Version"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.nVersion )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Issuer"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pIssuer )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Serial"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pSerial )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("KeyEncAlg"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pKeyEncAlg )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("EncKey"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pEncKey )));

        pCurList = pCurList->pNext;
    }

end :
    JS_PKCS7_resetEnvelopedData( &sEnvelopedData );
    if( pInfoList ) JS_PKCS7_resetRecipInfoList( &pInfoList );
}

void CMSInfoDlg::setSignedAndEnveloped()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);
    JSignedAndEnvelopedData sSignAndEnveloped;
    JSignerInfoList *pSignerList = NULL;
    JSignerInfoList *pCurSignerList = NULL;

    JRecipInfoList *pRecipList = NULL;
    JRecipInfoList *pCurRecipList = NULL;

    memset( &sSignAndEnveloped, 0x00, sizeof(sSignAndEnveloped));

    ret = JS_PKCS7_getSignedAndEnvelopedData( &cms_bin_, &sSignAndEnveloped, &pSignerList, &pRecipList );

    mVersionText->setText( QString("%1").arg( sSignAndEnveloped.nVersion ));
    mDataText->setPlainText( getHexString( &sSignAndEnveloped.binEncData ));

    if( sSignAndEnveloped.nMDCnt > 0 )
    {
        QString strAlg;
        JStrList *pCurList = sSignAndEnveloped.pMDList;

        while( pCurList )
        {
            if( strAlg.length() < 1 )
                strAlg = pCurList->pStr;
            else
                strAlg = QString( ";%1" ).arg( pCurList->pStr );

            pCurList = pCurList->pNext;
        }

        //    mDigestAlgText->setText( strAlg );
        mDataTable->insertRow(row);
        mDataTable->setItem( row, 0, new QTableWidgetItem("Digest Alg"));
        mDataTable->setItem( row, 1, new QTableWidgetItem( strAlg));
    }

    for( int i = 0; i < sSignAndEnveloped.nCertCnt; i++ )
    {
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        ret = JS_PKI_getCertInfo( &sSignAndEnveloped.pCertList[i], &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.uNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.uNotAfter, sNotAfter );

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.uNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        mCertTable->setItem( i, 0, item );
        mCertTable->setItem( i, 1, new QTableWidgetItem( sNotAfter ));
        mCertTable->setItem( i, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_PKI_resetCertInfo( &sCertInfo );
    }

    for( int i = 0; i < sSignAndEnveloped.nCRLCnt; i++ )
    {
        JCRLInfo sCRLInfo;

        char    sThisUpdate[64];
        char    sNextUpdate[64];

        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        ret = JS_PKI_getCRLInfo( &sSignAndEnveloped.pCRLList[i], &sCRLInfo, NULL, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCRLInfo.uThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.uNextUpdate, sNextUpdate );

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.uNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    mDataTable->insertRow(++row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("ContentType"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pContentType ));

    mDataTable->insertRow(++row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pAlg ));

    mDataTable->insertRow(++row);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Cipher"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pCipher ));

    pCurSignerList = pSignerList;

    while( pCurSignerList )
    {
        int idx = 0;
        mSignerTable->insertRow(idx);
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Version"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.nVersion )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Issuer"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.pIssuer )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("Serial"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.pSerial )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("DigestAlg"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.pDigestAlg )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("DigestEncAlg"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.pDigestEncAlg )));

        mSignerTable->insertRow( ++idx );
        mSignerTable->setItem( idx, 0, new QTableWidgetItem("EncDigest"));
        mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurSignerList->sSignerInfo.pEncDigest )));

        if( pCurSignerList->sSignerInfo.pAuthAttr )
        {
            JNumValList *pCurValList = pCurSignerList->sSignerInfo.pAuthAttr;

            while( pCurValList )
            {
                mSignerTable->insertRow( ++idx );
                mSignerTable->setItem( idx, 0, new QTableWidgetItem("AuthAttr"));
                mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                pCurValList = pCurValList->pNext;
            }
        }

        if( pCurSignerList->sSignerInfo.pUnauthAttr )
        {
            JNumValList *pCurValList = pCurSignerList->sSignerInfo.pUnauthAttr;

            while( pCurValList )
            {
                mSignerTable->insertRow( ++idx );
                mSignerTable->setItem( idx, 0, new QTableWidgetItem("UnauthAttr"));
                mSignerTable->setItem( idx, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                pCurValList = pCurValList->pNext;
            }
        }

        pCurSignerList = pCurSignerList->pNext;
    }

    pCurRecipList = pRecipList;

    while( pCurRecipList )
    {
        int idx = 0;
        mRecipTable->insertRow(idx);
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Version"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurRecipList->sRecipInfo.nVersion )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Issuer"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurRecipList->sRecipInfo.pIssuer )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("Serial"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurRecipList->sRecipInfo.pSerial )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("KeyEncAlg"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurRecipList->sRecipInfo.pKeyEncAlg )));

        mRecipTable->insertRow( ++idx );
        mRecipTable->setItem( idx, 0, new QTableWidgetItem("EncKey"));
        mRecipTable->setItem( idx, 1, new QTableWidgetItem( QString( "%1").arg( pCurRecipList->sRecipInfo.pEncKey )));

        pCurRecipList = pCurRecipList->pNext;
    }

end :
    JS_PKCS7_resetSignedAndEnvelopedData( &sSignAndEnveloped );
    if( pSignerList ) JS_PKCS7_resetSignerInfoList( &pSignerList );
    if( pRecipList ) JS_PKCS7_resetRecipInfoList( &pRecipList );
}
