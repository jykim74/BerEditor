#include <QDateTime>

#include "cms_info_dlg.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"
#include "tst_info_dlg.h"

#include "js_pki.h"
#include "js_pkcs7.h"
#include "js_util.h"
#include "js_pki_tools.h"
#include "js_ber.h"
#include "js_tsp.h"
#include "js_cms.h"
#include "js_error.h"

#include "common.h"

CMSInfoDlg::CMSInfoDlg(QWidget *parent, bool bCMS ) :
    QDialog(parent)
{
    is_cms_ = bCMS;
    memset( &cms_bin_, 0x00, sizeof(BIN));
    memset( &tsp_bin_, 0x00, sizeof(BIN));

    setupUi(this);

    connect( mViewTSPBtn, SIGNAL(clicked()), this, SLOT(clickViewTSP()));
    connect( mViewTSTBtn, SIGNAL(clicked()), this, SLOT(clickViewTST()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));

    connect( mDataTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickDataField(QModelIndex)));
    connect( mSignerTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickSignerField(QModelIndex)));
    connect( mRecipTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickRecipField(QModelIndex)));

    connect( mCertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCert()));
    connect( mCRLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCRL()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mDecodeDataBtn->setFixedWidth(34);
    mDecodeBtn->setFixedWidth(34);

    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mCertTab->layout()->setSpacing(5);
    mCertTab->layout()->setMargin(5);
    mCRLTab->layout()->setSpacing(5);
    mCRLTab->layout()->setMargin(5);
    mSignerTab->layout()->setSpacing(5);
    mSignerTab->layout()->setMargin(5);
    mRecipTab->layout()->setSpacing(5);
    mRecipTab->layout()->setMargin(5);
#endif
    initUI();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CMSInfoDlg::~CMSInfoDlg()
{
    JS_BIN_reset( &cms_bin_ );
    JS_BIN_reset( &tsp_bin_ );
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
    mDataTable->setColumnWidth( 0, nWidth * 3/10 );

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
    mSignerTable->setColumnWidth( 0, nWidth * 3/10 );

    mRecipTable->clear();
    mRecipTable->horizontalHeader()->setStretchLastSection(true);
    mRecipTable->setColumnCount( sDataLabels.size() );
    mRecipTable->setHorizontalHeaderLabels( sDataLabels );
    mRecipTable->verticalHeader()->setVisible(false);
    mRecipTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRecipTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRecipTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mRecipTable->setColumnWidth( 0, nWidth * 3/10 );

    mInfoTab->setCurrentIndex(0);
    mInfoTab->setTabEnabled( JS_CMS_CERT_IDX, false );
    mInfoTab->setTabEnabled( JS_CMS_CRL_IDX, false );
    mInfoTab->setTabEnabled( JS_CMS_SIGNER_IDX, false );
    mInfoTab->setTabEnabled( JS_CMS_RECIP_IDX, false );

    mViewTSPBtn->setEnabled( false );
    mViewTSTBtn->setEnabled( false );
}

void CMSInfoDlg::setTitle( const QString strName )
{
    QString strTitle = "CMS";

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

    setWindowTitle( strTitle );
}

void CMSInfoDlg::setCMS( const QString strPath )
{
    BIN binCMS = {0,0};
    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCMS );

    if( binCMS.nLen > 0 ) setCMS( &binCMS, strPath );

    cms_path_ = strPath;

    JS_BIN_reset( &binCMS );
}

void CMSInfoDlg::setCMS( const BIN *pCMS, const QString strTitle )
{
    QString strType;

    if( is_cms_ )
        cms_type_ = JS_CMS_getType( pCMS );
    else
        cms_type_ = JS_PKCS7_getType( pCMS );

    JS_BIN_reset( &cms_bin_ );
    JS_BIN_copy( &cms_bin_, pCMS );

    if( cms_type_ == JS_PKCS7_TYPE_SIGNED )
    {
        if( is_cms_ )
            setSignedCMS();
        else
            setSigned();

        strType = "Signed";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_ENVELOED )
    {
        if( is_cms_ )
            setEnvelopedCMS();
        else
            setEnveloped();

        strType = "Enveloped";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_SIGNED_AND_ENVELOPED )
    {
        setSignedAndEnveloped();
        strType = "SignedAndEnveloped";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_DATA )
    {
        setData();
        strType = "Data";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_DIGEST )
    {
        setDigest();
        strType = "Digest";
    }
    else if( cms_type_ == JS_PKCS7_TYPE_ENCRYPTED )
    {
        setEncrypted();
        strType = "Encrypted";
    }
    else
    {
        berApplet->warningBox( tr( "This type(%1) is not supported" ).arg( cms_type_ ), this );
    }

    setTitle( strTitle );
    mTypeText->setText( strType );
    if( tsp_bin_.nLen > 0 )
    {
        mViewTSPBtn->setEnabled( true );
        mViewTSTBtn->setEnabled( true );
    }
}

void CMSInfoDlg::dataChanged()
{
    QString strData = mDataText->toPlainText();

    QString strLen = getDataLenString( DATA_HEX, strData );
    mDataLenText->setText( QString("%1").arg( strLen ));
}

void CMSInfoDlg::clickDecode()
{
    berApplet->decodeData( &cms_bin_, cms_path_ );
}

void CMSInfoDlg::clickDataField(QModelIndex index)
{
    int row = index.row();
    QTableWidgetItem *item0 = mDataTable->item( row, 0 );
    QTableWidgetItem* item1 = mDataTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    mValueText->setPlainText( item0->text() );
    mValueText->appendPlainText( item1->text() );
}

void CMSInfoDlg::clickSignerField(QModelIndex index)
{
    int row = index.row();
    QTableWidgetItem *item0 = mSignerTable->item( row, 0 );
    QTableWidgetItem* item1 = mSignerTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    mValueText->setPlainText( item0->text() );
    mValueText->appendPlainText( item1->text() );
}

void CMSInfoDlg::clickRecipField(QModelIndex index)
{
    int row = index.row();
    QTableWidgetItem *item0 = mRecipTable->item( row, 0 );
    QTableWidgetItem* item1 = mRecipTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    mValueText->setPlainText( item0->text() );
    mValueText->appendPlainText( item1->text() );
}

void CMSInfoDlg::clickViewCert()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem* item = mCertTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    QString strHex = item->data(Qt::UserRole).toString();
    BIN binCert = {0,0};

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binCert );

    CertInfoDlg certInfo;
    certInfo.setCertBIN( &binCert );
    certInfo.exec();

    JS_BIN_reset( &binCert );
}

void CMSInfoDlg::clickViewCRL()
{
    QModelIndex idx = mCRLTable->currentIndex();
    QTableWidgetItem* item = mCRLTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    QString strHex = item->data(Qt::UserRole).toString();
    BIN binCRL = {0,0};

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binCRL );

    CRLInfoDlg crlInfo;
    crlInfo.setCRL_BIN( &binCRL );
    crlInfo.exec();

    JS_BIN_reset( &binCRL );
}

void CMSInfoDlg::clickViewTSP()
{
    if( tsp_bin_.nLen <= 0 ) return;

    CMSInfoDlg cmsInfo;
    cmsInfo.setCMS( &tsp_bin_, "Time Stamp" );
    cmsInfo.exec();
}

void CMSInfoDlg::clickViewTST()
{
    int ret = 0;
    BIN binTST = {0,0};

    if( tsp_bin_.nLen <= 0 ) return;

    ret = JS_TSP_getTST( &tsp_bin_, &binTST );

    if( binTST.nLen > 0 )
    {
        TSTInfoDlg tstInfo;
        tstInfo.setTST( &binTST );
        tstInfo.exec();

        JS_BIN_reset( &binTST );
    }
}

void CMSInfoDlg::setSignerInfo( const JP7SignerInfoList *pSignerList )
{
    int srow = 0;
    const JP7SignerInfoList *pCurList = NULL;

    if( pSignerList == NULL ) return;

    pCurList = pSignerList;

    while( pCurList )
    {
        char    sSignTime[64];

        memset( sSignTime, 0x00, sizeof(sSignTime));

        mSignerTable->insertRow(srow);
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Version") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "V%1").arg( pCurList->sSignerInfo.nVersion + 1)));
        srow++;

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Issuer") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pIssuer )));
        srow++;

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Serial") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pSerial )));
        srow++;

        JS_UTIL_getDateTime( pCurList->sSignerInfo.tSignTime, sSignTime );

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("SignTime") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( sSignTime )));
        srow++;

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("DigestAlg") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pDigestAlg )));
        srow++;

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("DigestEncAlg") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pDigestEncAlg )));
        srow++;

        mSignerTable->insertRow( srow );
        mSignerTable->setRowHeight(srow, 10);
        mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("EncDigest") ));
        mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sSignerInfo.pEncDigest )));
        srow++;

        if( pCurList->sSignerInfo.pAuthAttr )
        {
            JNumValList *pCurValList = pCurList->sSignerInfo.pAuthAttr;

            while( pCurValList )
            {
                if( pCurValList->sNumVal.pValue )
                {
                    QString strSN = JS_PKI_getSNFromNid( pCurValList->sNumVal.nNum );
                    mSignerTable->insertRow( srow );
                    mSignerTable->setRowHeight(srow, 10);
                    mSignerTable->setItem( srow, 0, new QTableWidgetItem( QString( "[A]%1" ).arg( strSN )) );
                    mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                    berApplet->log( QString("%1:%2").arg( strSN ).arg( pCurValList->sNumVal.pValue ));
                    srow++;
                }

                pCurValList = pCurValList->pNext;
            }
        }

        if( pCurList->sSignerInfo.pUnauthAttr )
        {
            JNumValList *pCurValList = pCurList->sSignerInfo.pUnauthAttr;

            while( pCurValList )
            {
                if( pCurValList->sNumVal.pValue )
                {
                    QString strSN = JS_PKI_getSNFromNid( pCurValList->sNumVal.nNum );

                    mSignerTable->insertRow( srow );
                    mSignerTable->setRowHeight(srow, 10);
                    mSignerTable->setItem( srow, 0, new QTableWidgetItem( QString("[U]%1").arg( strSN )));
                    mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                    berApplet->log( QString("%1:%2").arg( strSN ).arg( pCurValList->sNumVal.pValue ));
                    srow++;
                }

                pCurValList = pCurValList->pNext;
            }
        }

        pCurList = pCurList->pNext;

        if( pCurList )
        {
            mSignerTable->insertRow( srow );
            mSignerTable->setRowHeight( srow, 10 );

            srow++;
        }
    }
}

void CMSInfoDlg::setRecipInfo( const JP7RecipInfoList *pRecipList )
{
    int rrow = 0;
    const JP7RecipInfoList *pCurList = NULL;

    if( pRecipList == NULL ) return;

    pCurList = pRecipList;

    while( pCurList )
    {
        mRecipTable->insertRow(rrow);
        mRecipTable->setRowHeight(rrow, 10);
        mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr("Version") ));
        mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "V%1").arg( pCurList->sRecipInfo.nVersion + 1 )));
        rrow++;

        mRecipTable->insertRow( rrow );
        mRecipTable->setRowHeight(rrow, 10);
        mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr("Issuer") ));
        mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pIssuer )));
        rrow++;

        mRecipTable->insertRow( rrow );
        mRecipTable->setRowHeight(rrow, 10);
        mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "Serial" ) ));
        mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pSerial )));
        rrow++;

        mRecipTable->insertRow( rrow );
        mRecipTable->setRowHeight(rrow, 10);
        mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "KeyEncAlg" )));
        mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pKeyEncAlg )));
        rrow++;

        mRecipTable->insertRow( rrow );
        mRecipTable->setRowHeight(rrow, 10);
        mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "EncKey" )));
        mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sRecipInfo.pEncKey )));
        rrow++;

        if( pCurList->sRecipInfo.binCert.nLen > 0 )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight(rrow, 10);
            mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "Certificate" )));
            mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( getHexString( &pCurList->sRecipInfo.binCert ) )));
            rrow++;
        }

        pCurList = pCurList->pNext;

        if( pCurList )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight( rrow, 10 );
            rrow++;
        }
    }
}

void CMSInfoDlg::setSignerInfoCMS( const JSignerInfoList *pSignerList )
{
    int srow = 0;
    const JSignerInfoList *pCurList = NULL;

    if( pSignerList == NULL ) return;

    pCurList = pSignerList;

    while( pCurList )
    {
        if( pCurList->sInfo.pAlg )
        {
            mSignerTable->insertRow(srow);
            mSignerTable->setRowHeight(srow, 10);
            mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Alg") ));
            mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sInfo.pAlg )));
            srow++;
        }

        if( pCurList->sInfo.pHash )
        {
            mSignerTable->insertRow( srow );
            mSignerTable->setRowHeight(srow, 10);
            mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Hash") ));
            mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sInfo.pHash )));
            srow++;
        }

        if( pCurList->sInfo.binSign.nLen > 0 )
        {
            mSignerTable->insertRow( srow );
            mSignerTable->setRowHeight(srow, 10);
            mSignerTable->setItem( srow, 0, new QTableWidgetItem( tr("Signature") ));
            mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString( "%1").arg( getHexString( &pCurList->sInfo.binSign ) )));
            srow++;
        }

        if( pCurList->sInfo.pAuthAttr )
        {
            JNumValList *pCurValList = pCurList->sInfo.pAuthAttr;

            while( pCurValList )
            {
                if( pCurValList->sNumVal.pValue )
                {
                    QString strSN = JS_PKI_getSNFromNid( pCurValList->sNumVal.nNum );
                    mSignerTable->insertRow( srow );
                    mSignerTable->setRowHeight(srow, 10);
                    mSignerTable->setItem( srow, 0, new QTableWidgetItem( QString( "[A]%1" ).arg( strSN )) );
                    mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                    berApplet->log( QString("%1:%2").arg( strSN ).arg( pCurValList->sNumVal.pValue ));
                    srow++;
                }

                pCurValList = pCurValList->pNext;
            }
        }

        if( pCurList->sInfo.pUnauthAttr )
        {
            JNumValList *pCurValList = pCurList->sInfo.pUnauthAttr;

            while( pCurValList )
            {
                if( pCurValList->sNumVal.pValue )
                {
                    QString strSN = JS_PKI_getSNFromNid( pCurValList->sNumVal.nNum );

                    mSignerTable->insertRow( srow );
                    mSignerTable->setRowHeight(srow, 10);
                    mSignerTable->setItem( srow, 0, new QTableWidgetItem( QString("[U]%1").arg( strSN )));
                    mSignerTable->setItem( srow, 1, new QTableWidgetItem( QString("%1").arg( pCurValList->sNumVal.pValue )));

                    berApplet->log( QString("%1:%2").arg( strSN ).arg( pCurValList->sNumVal.pValue ));
                    srow++;
                }

                pCurValList = pCurValList->pNext;
            }
        }

        pCurList = pCurList->pNext;

        if( pCurList )
        {
            mSignerTable->insertRow( srow );
            mSignerTable->setRowHeight( srow, 10 );

            srow++;
        }
    }
}

void CMSInfoDlg::setRecipInfoCMS( const JRecipInfoList *pRecipList )
{
    int rrow = 0;
    const JRecipInfoList *pCurList = NULL;

    if( pRecipList == NULL ) return;

    pCurList = pRecipList;

    while( pCurList )
    {
        if( pCurList->sInfo.pAlg )
        {
            mRecipTable->insertRow(rrow);
            mRecipTable->setRowHeight(rrow, 10);
            mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr("Alg") ));
            mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sInfo.pAlg )));
            rrow++;
        }

        if( pCurList->sInfo.pIssuer )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight(rrow, 10);
            mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr("Issuer") ));
            mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sInfo.pIssuer )));
            rrow++;
        }

        if( pCurList->sInfo.pSerial )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight(rrow, 10);
            mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "Serial" ) ));
            mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( pCurList->sInfo.pSerial )));
            rrow++;
        }

        if( pCurList->sInfo.binCert.nLen > 0 )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight(rrow, 10);
            mRecipTable->setItem( rrow, 0, new QTableWidgetItem( tr( "Certificate" )));
            mRecipTable->setItem( rrow, 1, new QTableWidgetItem( QString( "%1").arg( getHexString( &pCurList->sInfo.binCert ) )));
            rrow++;
        }

        pCurList = pCurList->pNext;

        if( pCurList )
        {
            mRecipTable->insertRow( rrow );
            mRecipTable->setRowHeight( rrow, 10 );
            rrow++;
        }
    }
}

void CMSInfoDlg::setSigned()
{
    int ret = 0;
    int row = 0;

    JP7SignedData sSignedData;
    JP7SignerInfoList *pInfoList = NULL;

    time_t now = time(NULL);
    QString strCAPath = berApplet->settingsMgr()->CACertPath();

    memset( &sSignedData, 0x00, sizeof(sSignedData));
    JS_BIN_reset( &tsp_bin_ );

    ret = JS_PKCS7_getSignedData( &cms_bin_, strCAPath.toStdString().c_str(), &sSignedData, &pInfoList, &tsp_bin_ );

    mVersionText->setText( QString("V%1").arg( sSignedData.nVersion + 1 ));
    mDataText->setPlainText( getHexString( &sSignedData.binContent ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignedData.pType ));
    row++;

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
        mDataTable->setRowHeight( row, 10 );
        mDataTable->setItem( row, 0, new QTableWidgetItem("Digest Alg"));
        mDataTable->setItem( row, 1, new QTableWidgetItem( strAlg));
        row++;
    }

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Verify" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sSignedData.nVerify )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Cert Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sSignedData.nCertCnt )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "CRL Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sSignedData.nCRLCnt )));
    row++;

    if( sSignedData.nCertCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CERT_IDX, true );
    if( sSignedData.nCRLCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CRL_IDX, true );

    for( int i = 0; i < sSignedData.nCertCnt; i++ )
    {
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        ret = JS_PKI_getCertInfo( &sSignedData.pCertList[i], &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, getHexString( &sSignedData.pCertList[i] ));

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

        JS_UTIL_getDate( sCRLInfo.tThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.tNextUpdate, sNextUpdate );

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.tNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        item->setData( Qt::UserRole, getHexString( &sSignedData.pCRLList[i] ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    if( pInfoList )
    {
        mInfoTab->setTabEnabled( JS_CMS_SIGNER_IDX, true );
        setSignerInfo( pInfoList );
    }

    JS_PKCS7_resetSignedData( &sSignedData );
    if( pInfoList ) JS_PKCS7_resetSignerInfoList( &pInfoList );
}

void CMSInfoDlg::setEnveloped()
{
    int ret = 0;
    int row = 0;

    JP7EnvelopedData sEnvelopedData;
    JP7RecipInfoList *pInfoList = NULL;

    memset( &sEnvelopedData, 0x00, sizeof(sEnvelopedData));

    ret = JS_PKCS7_getEnvelopedData( &cms_bin_, &sEnvelopedData, &pInfoList );

    if( ret != 0 ) goto end;

    mVersionText->setText( QString("V%1").arg( sEnvelopedData.nVersion + 1));
    mDataText->setPlainText( getHexString( &sEnvelopedData.binEncData ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("ContentType"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pContentType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEnvelopedData.pAlg ));
    row++;


    if( pInfoList )
    {
        mInfoTab->setTabEnabled( JS_CMS_RECIP_IDX, true );
        setRecipInfo( pInfoList );
    }

end :
    JS_PKCS7_resetEnvelopedData( &sEnvelopedData );
    if( pInfoList ) JS_PKCS7_resetRecipInfoList( &pInfoList );
}

void CMSInfoDlg::setSignedCMS()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    JCMSInfo sCMS;
    JSignerInfoList *pInfoList = NULL;
    int nCertCnt = 0;
    int nCRLCnt = 0;
    int nInfoCnt = 0;

    mVersionLabel->setEnabled(false);
    mVersionText->setEnabled( false );

    memset( &sCMS, 0x00, sizeof(sCMS));
    JS_BIN_reset( &tsp_bin_ );

    ret = JS_CMS_getSignedData( &cms_bin_, &sCMS, &pInfoList, &tsp_bin_ );

    nCertCnt = JS_BIN_countList( sCMS.pCertList );
    nCRLCnt = JS_BIN_countList( sCMS.pCRLList );
    nInfoCnt = JS_CMS_SginerInfo_countList( pInfoList );

    mDataText->setPlainText( getHexString( &sCMS.binContent ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( JS_CMS_getTypeName( sCMS.nType ) ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Verify" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sCMS.nVerify )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Cert Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nCertCnt )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "CRL Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nCRLCnt )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Signer Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nInfoCnt )));
    row++;

    if( nCertCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CERT_IDX, true );
    if( nCRLCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CRL_IDX, true );

    for( int i = 0; i < nCertCnt; i++ )
    {
        const BINList *pCertList = NULL;
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        pCertList = JS_BIN_getListAt( i, sCMS.pCertList );

        ret = JS_PKI_getCertInfo( &pCertList->Bin, &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, getHexString( &pCertList->Bin ));

        mCertTable->setItem( i, 0, item );
        mCertTable->setItem( i, 1, new QTableWidgetItem( sNotAfter ));
        mCertTable->setItem( i, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_PKI_resetCertInfo( &sCertInfo );
    }

    for( int i = 0; i < nCRLCnt; i++ )
    {
        JCRLInfo sCRLInfo;
        const BINList *pCRLList = NULL;

        char    sThisUpdate[64];
        char    sNextUpdate[64];

        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        pCRLList = JS_BIN_getListAt( i, sCMS.pCRLList );

        ret = JS_PKI_getCRLInfo( &pCRLList->Bin, &sCRLInfo, NULL, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCRLInfo.tThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.tNextUpdate, sNextUpdate );

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.tNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        item->setData( Qt::UserRole, getHexString( &pCRLList->Bin ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    if( pInfoList )
    {
        mInfoTab->setTabEnabled( JS_CMS_SIGNER_IDX, true );
        setSignerInfoCMS( pInfoList );
    }

    JS_CMS_resetCMSInfo( &sCMS );
    if( pInfoList ) JS_CMS_resetSignerInfoList( &pInfoList );
}

void CMSInfoDlg::setEnvelopedCMS()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    JCMSInfo sCMS;
    JRecipInfoList *pInfoList = NULL;
    int nCertCnt = 0;
    int nCRLCnt = 0;
    int nInfoCnt = 0;

    mVersionLabel->setEnabled(false);
    mVersionText->setEnabled( false );

    memset( &sCMS, 0x00, sizeof(sCMS));
    JS_BIN_reset( &tsp_bin_ );

    ret = JS_CMS_getEnvelopedData( &cms_bin_, &sCMS, &pInfoList );

    nCertCnt = JS_BIN_countList( sCMS.pCertList );
    nCRLCnt = JS_BIN_countList( sCMS.pCRLList );
    nInfoCnt = JS_CMS_RecipInfo_countList( pInfoList );

    mDataText->setPlainText( getHexString( &sCMS.binContent ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( JS_CMS_getTypeName( sCMS.nType ) ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Cert Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nCertCnt )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "CRL Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nCRLCnt )));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Recip Count" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( nInfoCnt )));
    row++;

    if( nCertCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CERT_IDX, true );
    if( nCRLCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CRL_IDX, true );

    for( int i = 0; i < nCertCnt; i++ )
    {
        const BINList *pCertList = NULL;
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        pCertList = JS_BIN_getListAt( i, sCMS.pCertList );

        ret = JS_PKI_getCertInfo( &pCertList->Bin, &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, getHexString( &pCertList->Bin ));

        mCertTable->setItem( i, 0, item );
        mCertTable->setItem( i, 1, new QTableWidgetItem( sNotAfter ));
        mCertTable->setItem( i, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_PKI_resetCertInfo( &sCertInfo );
    }

    for( int i = 0; i < nCRLCnt; i++ )
    {
        JCRLInfo sCRLInfo;
        const BINList *pCRLList = NULL;

        char    sThisUpdate[64];
        char    sNextUpdate[64];

        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        pCRLList = JS_BIN_getListAt( i, sCMS.pCRLList );

        ret = JS_PKI_getCRLInfo( &pCRLList->Bin, &sCRLInfo, NULL, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCRLInfo.tThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.tNextUpdate, sNextUpdate );

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.tNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        item->setData( Qt::UserRole, getHexString( &pCRLList->Bin ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    if( pInfoList )
    {
        mInfoTab->setTabEnabled( JS_CMS_RECIP_IDX, true );
        setRecipInfoCMS( pInfoList );
    }

    JS_CMS_resetCMSInfo( &sCMS );
    if( pInfoList ) JS_CMS_resetRecipInfoList( &pInfoList );
}

void CMSInfoDlg::setSignedAndEnveloped()
{
    int ret = 0;
    int row = 0;

    time_t now = time(NULL);
    JP7SignedAndEnvelopedData sSignAndEnveloped;
    JP7SignerInfoList *pSignerList = NULL;
    JP7RecipInfoList *pRecipList = NULL;

    QString strCAPath = berApplet->settingsMgr()->CACertPath();

    memset( &sSignAndEnveloped, 0x00, sizeof(sSignAndEnveloped));
    JS_BIN_reset( &tsp_bin_ );

    ret = JS_PKCS7_getSignedAndEnvelopedData( &cms_bin_, strCAPath.toStdString().c_str(), &sSignAndEnveloped, &pSignerList, &pRecipList, &tsp_bin_ );
    if( ret != 0 ) goto end;

    mVersionText->setText( QString("V%1").arg( sSignAndEnveloped.nVersion + 1));
    mDataText->setPlainText( getHexString( &sSignAndEnveloped.binEncData ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pType ));
    row++;

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
        mDataTable->setRowHeight(row, 10);
        mDataTable->setItem( row, 0, new QTableWidgetItem("Digest Alg"));
        mDataTable->setItem( row, 1, new QTableWidgetItem( strAlg));
        row++;
    }

    if( sSignAndEnveloped.nCertCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CERT_IDX, true );
    if( sSignAndEnveloped.nCRLCnt > 0 ) mInfoTab->setTabEnabled( JS_CMS_CRL_IDX, true );


    for( int i = 0; i < sSignAndEnveloped.nCertCnt; i++ )
    {
        JCertInfo sCertInfo;

        char    sNotBefore[64];
        char    sNotAfter[64];

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        ret = JS_PKI_getCertInfo( &sSignAndEnveloped.pCertList[i], &sCertInfo, NULL );
        if( ret != 0 ) continue;

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mCertTable->insertRow( i );
        mCertTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, getHexString( &sSignAndEnveloped.pCertList[i] ));

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

        JS_UTIL_getDate( sCRLInfo.tThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.tNextUpdate, sNextUpdate );

        mCRLTable->insertRow( i );
        mCRLTable->setRowHeight( i, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.tNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        item->setData( Qt::UserRole, getHexString( &sSignAndEnveloped.pCRLList[i] ));

        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem( sThisUpdate ));
        mCRLTable->setItem( i, 2, new QTableWidgetItem( sNextUpdate ));


        JS_PKI_resetCRLInfo( &sCRLInfo );
    }

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row,10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("ContentType"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pContentType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row,10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sSignAndEnveloped.pAlg ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem( "Verify" ));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sSignAndEnveloped.nVerify )));
    row++;


    if( pSignerList )
    {
        mInfoTab->setTabEnabled( JS_CMS_SIGNER_IDX, true );
        setSignerInfo( pSignerList );
    }

    if( pRecipList )
    {
        mInfoTab->setTabEnabled( JS_CMS_RECIP_IDX, true );
        setRecipInfo( pRecipList );
    }

end :
    JS_PKCS7_resetSignedAndEnvelopedData( &sSignAndEnveloped );
    if( pSignerList ) JS_PKCS7_resetSignerInfoList( &pSignerList );
    if( pRecipList ) JS_PKCS7_resetRecipInfoList( &pRecipList );
}

void CMSInfoDlg::setData()
{
    int ret = 0;
    int row = 0;
    JP7Data sData;

    memset( &sData, 0x00, sizeof(sData));

    ret = JS_PKCS7_getData( &cms_bin_, &sData );
    if( ret != 0 ) return;

    mVersionText->clear();
    mDataText->setPlainText( getHexString( &sData.binData ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sData.pType ));
    row++;

    JS_PKCS7_resetData( &sData );
}

void CMSInfoDlg::setDigest()
{
    int ret = 0;
    int row = 0;

    JP7DigestData sDigestData;

    memset( &sDigestData, 0x00, sizeof(sDigestData));

    ret = JS_PKCS7_getDigestData( &cms_bin_, &sDigestData );
    if( ret != JSR_OK ) return;

    mVersionText->setText( QString("V%1").arg( sDigestData.nVersion + 1 ));
    mDataText->setPlainText( getHexString( &sDigestData.binContent ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight( row, 10 );
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sDigestData.pType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Digest"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sDigestData.pDigest ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sDigestData.pAlg ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Verify"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( QString("%1").arg( sDigestData.nVerify ) ));
    row++;

end :
    JS_PKCS7_resetDigestData( &sDigestData );
}

void CMSInfoDlg::setEncrypted()
{
    int ret = 0;
    int row = 0;
    JP7EncryptedData sEncryptData;

    memset( &sEncryptData, 0x00, sizeof(sEncryptData));

    ret = JS_PKCS7_getEncryptedData( &cms_bin_, &sEncryptData );
    if( ret != 0 ) goto end;

    mVersionText->setText( QString("V%1").arg( sEncryptData.nVersion + 1 ));
    mDataText->setPlainText( getHexString( &sEncryptData.binEncData ));

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Type"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEncryptData.pType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("ContentType"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEncryptData.pContentType ));
    row++;

    mDataTable->insertRow(row);
    mDataTable->setRowHeight(row, 10);
    mDataTable->setItem( row, 0, new QTableWidgetItem("Alg"));
    mDataTable->setItem( row, 1, new QTableWidgetItem( sEncryptData.pAlg ));
    row++;

end :
    JS_PKCS7_resetEncryptedData( &sEncryptData );
}
