#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamReader>
#include <QFileInfo>
#include <QDateTime>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDir>
#include <QMenu>
#include <QClipboard>
#include <QTemporaryFile>

#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "common.h"
#include "json_tree_dlg.h"
#include "acme_object.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "key_list_dlg.h"
#include "cms_info_dlg.h"
#include "time_stamp_dlg.h"
#include "export_dlg.h"
#include "data_input_dlg.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "cert_id_dlg.h"
#include "cms_info_dlg.h"
#include "tst_info_dlg.h"
#include "cert_info_dlg.h"
#include "cert_pvd_dlg.h"
#include "ocsp_rsp_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"
#include "js_pki_xml.h"
#include "js_pkcs7.h"
#include "js_cms.h"
#include "js_error.h"
#include "js_tsp.h"
#include "js_http.h"
#include "js_pdf.h"
#include "js_pki_tools.h"
#include "js_tsp.h"
#include "js_ocsp.h"

#include "pdf_signer_dlg.h"

#ifdef PDF_SIGN

PDFSignerDlg::PDFSignerDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();
    setAcceptDrops( true );

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mSrcFindBtn, SIGNAL(clicked()), this, SLOT(findSrcPath()));
    connect( mDstFindBtn, SIGNAL(clicked()), this, SLOT(findDstPath()));

    connect( mInfoTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTableMenuRequested(QPoint)));
    connect( mDSSTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotTreeMenuRequested(QPoint)));
    connect( mPathTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotPathTreeMenuRequest(QPoint)));
    connect( mPathTree, SIGNAL(itemDoubleClicked(QTreeWidgetItem*,int)), this, SLOT(viewPathTreeData()));

    connect( mDSSCheck, SIGNAL(clicked()), this, SLOT(checkDSS()));
    connect( mUseTSPCheck, SIGNAL(clicked()), this, SLOT(checkUseTSP()));
    connect( mTSPBtn, SIGNAL(clicked()), this, SLOT(clickTSP()));

    connect( mUseSubjectDNCheck, SIGNAL(clicked()), this, SLOT(checkNameSubjectDN()));
    connect( mGetInfoBtn, SIGNAL(clicked()), this, SLOT(clickGetInfo()));
    connect( mMakePathBtn, SIGNAL(clicked()), this, SLOT(clickMakePath()));
    connect( mInfoClearBtn, SIGNAL(clicked()), this, SLOT(clickClearInfo()));
    connect( mSignBtn, SIGNAL(clicked()), this, SLOT(clickMakeSign()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerifySign()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));

    connect( mViewSignerBtn, SIGNAL(clicked()), this, SLOT(clickViewSigner()));
    connect( mViewCMSBtn, SIGNAL(clicked()), this, SLOT(clickViewCMS()));
    connect( mExportCMSBtn, SIGNAL(clicked()), this, SLOT(clickExportCMS()));

    connect( mAddDSSBtn, SIGNAL(clicked()), this, SLOT(clickAddDSS()));
    connect( mAddDSS_VRIBtn, SIGNAL(clicked()), this, SLOT(clickAddDSS_VRI()));
    connect( mAddDocTSPBtn, SIGNAL(clicked()), this, SLOT(clickAddDocTSP()));
    connect( mViewDocTSPBtn, SIGNAL(clicked()), this, SLOT(clickViewDocTSP()));
    connect( mVerifyDocTSPBtn, SIGNAL(clicked()), this, SLOT(clickVerifyDocTSP()));
    connect( mViewDocTSP_TSTBtn, SIGNAL(clicked()), this, SLOT(clickViewDocTSP_TST()));
    connect( mVerifyDSSBtn, SIGNAL(clicked()), this, SLOT(clickVerifyDSS()));
    connect( mVerifyDSS_VRIBtn, SIGNAL(clicked()), this, SLOT(clickVerifyDSS_VRI()));

    connect( mExportByteRangeBtn, SIGNAL(clicked()), this, SLOT(clickExportByteRange()));
    connect( mExportDocTSPByteRangeBtn, SIGNAL(clicked()), this, SLOT(clickExportDocTSPByteRange()));
    connect( mDstPathUpBtn, SIGNAL(clicked()), this, SLOT(clickDstPathUp()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDstPathUpBtn->setFixedWidth(34);
    mInfoClearBtn->setFixedWidth(34);

    mInfoTab->layout()->setSpacing(5);
    mInfoTab->layout()->setMargin(5);
    mDSSTab->layout()->setSpacing(5);
    mDSSTab->layout()->setMargin(5);

    mSignTab->layout()->setSpacing(5);
    mSignTab->layout()->setMargin(5);
    mVerifyTab->layout()->setSpacing(5);
    mVerifyTab->layout()->setMargin(5);
    mEncTab->layout()->setSpacing(5);
    mEncTab->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

PDFSignerDlg::~PDFSignerDlg()
{

}

void PDFSignerDlg::initUI()
{
    QStringList sHeaders = { tr( "Name" ), tr( "Value" ) };
    mVRICombo->setEditable(true);

    mTabWidget->setCurrentIndex(0);

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(sHeaders.size());
    mInfoTable->setHorizontalHeaderLabels( sHeaders );
    mInfoTable->verticalHeader()->setVisible(false);
    mInfoTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mInfoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mInfoTable->setColumnWidth( 0, 120 );

    mNameText->setPlaceholderText( tr("String value" ));
    mReasonText->setPlaceholderText( tr( "String value" ));
    mLocationText->setPlaceholderText( tr("String value" ));
    mContactInfoText->setPlaceholderText( tr("String value" ));

    mDSSTree->clear();
    mDSSTree->header()->setVisible( false );
    mDSSTree->setColumnCount(1);

    QTreeWidgetItem* tItem = new QTreeWidgetItem;
    tItem->setIcon( 0, QIcon(":/images/pdf.png" ));
    tItem->setText( 0, kDSS );
    mDSSTree->insertTopLevelItem( 0, tItem );

    mPathTree->clear();
    mPathTree->header()->setVisible( false );
    mPathTree->setColumnCount(1);

    QTreeWidgetItem* pathItem = new QTreeWidgetItem;
    pathItem->setIcon( 0, QIcon(":/images/cert_pvd.png" ));
    pathItem->setText( 0, "Certificate Path" );
    mPathTree->insertTopLevelItem( 0, pathItem );

    checkDSS();
    mTypeTab->setCurrentIndex(0);
}

void PDFSignerDlg::initialize()
{
    QDateTime dateTime = QDateTime::currentDateTime();
    mDateTime->setDateTime( dateTime );
}

int PDFSignerDlg::getTSP( const BIN *pSrc, BIN *pTSP )
{
    int ret = 0;
    int nUseNonce = 0;


    QString strHash;
    QString strPolicy;
    const char *pPolicy = NULL;
    QString strURL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strAuth;
    int nStatus = -1;
    BIN binTST = {0,0};

    TimeStampDlg tspDlg;
    int nTSPStatus = 0;

    if( tspDlg.exec() != QDialog::Accepted )
        return -1;

    strURL = tspDlg.mURLCombo->currentText();
    strPolicy = tspDlg.mPolicyText->text();
    strHash = tspDlg.mHashCombo->currentText();

    if( tspDlg.mAuthGroup->isChecked() == true )
    {
        QString strUser = tspDlg.mUserNameText->text();
        QString strPass = tspDlg.mPasswdText->text();
        QString strUP;
        BIN bin = {0,0};
        char *pBase64 = NULL;


        strUP = QString( "%1:%2" ).arg( strUser ).arg( strPass );
        JS_BIN_set( &bin, (unsigned char *)strUP.toStdString().c_str(), strUP.length() );
        JS_BIN_encodeBase64( &bin, &pBase64 );
        strAuth = QString( "Basic %1").arg( pBase64 );

        JS_BIN_reset( &bin );
        if( pBase64 ) JS_free( pBase64 );
    }

    if( tspDlg.mUseNonceCheck->isChecked() == true )
        nUseNonce = 1;

    if( strPolicy.length() > 0 ) pPolicy = strPolicy.toStdString().c_str();

    ret = JS_TSP_encodeRequest( pSrc, strHash.toStdString().c_str(), pPolicy, nUseNonce, &binReq );
    if( ret != 0 ) goto end;

    if( tspDlg.mAuthGroup->isChecked() == true )
        ret = JS_HTTP_requestAuthPostBin( strURL.toStdString().c_str(), "application/tsp-request", strAuth.toStdString().c_str(), &binReq, &nStatus, &binRsp );
    else
        ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );

    if( ret != 0 ) goto end;

    ret = JS_TSP_decodeResponse( &binRsp, &nTSPStatus, pTSP, &binTST );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binTST );

    return ret;
}

int PDFSignerDlg::getPriKeyCert( BIN *pPriKey, BIN *pCert )
{
    QString strName;
    JCertInfo sCertInfo;
    CertManDlg certMan;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));
    certMan.setPQCEnable( false );

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getPriKey( pPriKey );
    certMan.getCert( pCert );
    strName = sCertInfo.pSubjectName;

    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

int PDFSignerDlg::getCert( BIN *pCert )
{
    JCertInfo sCertInfo;
    CertManDlg certMan;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    certMan.setMode( ManModeSelCert );
    certMan.setTitle( tr( "Select a sign certificate" ));
    certMan.setPQCEnable( false );

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getCert( pCert );
    JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

void PDFSignerDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void PDFSignerDlg::dropEvent(QDropEvent *event)
{
    BIN binData = {0,0};
    char *pString = NULL;

    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));

            mSrcPathText->setText( url.toLocalFile() );

            break;
        }
    } else if (event->mimeData()->hasText()) {

    }

end :
    JS_BIN_reset( &binData );
    if( pString ) JS_free( pString );
}

void PDFSignerDlg::copyValue()
{
    QModelIndex idx = mInfoTable->currentIndex();
    QTableWidgetItem* item = mInfoTable->item( idx.row(), 1 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( item->text() );

    berApplet->messageBox( tr( "The value has been copied." ), this );
}

void PDFSignerDlg::decodeValue()
{
    QModelIndex idx = mInfoTable->currentIndex();

    QTableWidgetItem* item0 = mInfoTable->item( idx.row(), 0 );
    QTableWidgetItem* item1 = mInfoTable->item( idx.row(), 1 );

    if( item1 == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QString strValue = item1->text();
    BIN binData = {0,0};

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binData );
    if( JS_PKI_isBER( &binData ) == false )
    {
        berApplet->warningBox( tr( "No avaiable BER" ), this );
        goto end;
    }

    berApplet->decodeTitle( &binData, item0->text() );

end :
    JS_BIN_reset( &binData );
}

void PDFSignerDlg::viewValue()
{
    QModelIndex idx = mInfoTable->currentIndex();

    QTableWidgetItem* item0 = mInfoTable->item( idx.row(), 0 );
    QTableWidgetItem* item1 = mInfoTable->item( idx.row(), 1 );

    if( item1 == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QString strType = item0->text();
    QString strValue = item1->text();
    BIN binData = {0,0};

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binData );

    if( JS_PKI_isBER( &binData ) == false )
    {
        berApplet->warningBox( tr( "No avaiable BER" ), this );
        goto end;
    }


    if( strType == kDSS_Cert )
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binData, strType );
        certInfo.exec();
    }
    else if( strType == kDSS_CRL )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &binData, strType );
        crlInfo.exec();
    }
    else if( strType == kDSS_OCSP )
    {
#if 0
        CertIDDlg certID;
        certID.setResponse2( &binData );
        certID.exec();
#else
        OCSPRspDlg ocspRsp;
        ocspRsp.setResponse( &binData );
        ocspRsp.exec();
#endif
    }
    else if( strType == kDocTimeStamp )
    {
        CMSInfoDlg cmsInfo;
        cmsInfo.setCMS( &binData, kDocTimeStamp );
        cmsInfo.exec();
    }

end :
    JS_BIN_reset( &binData );
}

void PDFSignerDlg::viewPathTreeData()
{
    BIN binData = {0,0};
    QTreeWidgetItem *item = mPathTree->currentItem();

    if( item == NULL ) return;

    QString strData = item->data( 0, Qt::UserRole ).toString();
    JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );

    int nType = item->data( 0, 99 ).toInt();

    if( nType == PVD_CRL )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &binData );
        crlInfo.exec();
    }
    else if( nType == PVD_OCSP )
    {
        OCSPRspDlg ocspRsp;
        ocspRsp.setResponse( &binData );
        ocspRsp.exec();
    }
    else
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binData );
        certInfo.exec();
    }

    JS_BIN_reset( &binData );
}

void PDFSignerDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QModelIndex idx = mInfoTable->currentIndex();
    QTableWidgetItem* item = mInfoTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QAction *copyValueAct = new QAction( tr( "Copy value" ), this );
    QAction *decodeAct = new QAction( tr( "Decode value" ), this );
    QAction *viewAct = new QAction( tr( "View value" ), this );

    QString strName = item->text();

    connect( copyValueAct, SIGNAL(triggered(bool)), this, SLOT(copyValue()));
    connect( decodeAct, SIGNAL(triggered(bool)), this, SLOT(decodeValue()));
    connect( viewAct, SIGNAL(triggered(bool)), this, SLOT(viewValue()));

    menu->addAction( copyValueAct );

    if( strName == kDSS_Cert || strName == kDSS_CRL || strName == kDSS_OCSP || strName == kDocTimeStamp )
    {
        menu->addAction( decodeAct );
        menu->addAction( viewAct );
    }

    menu->popup( mInfoTable->viewport()->mapToGlobal(pos));
}

void PDFSignerDlg::slotPathTreeMenuRequest( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction* viewAct = new QAction( tr("View" ), this );

    QTreeWidgetItem *item = mPathTree->currentItem();
    if( item == NULL ) return;

    if( item->data(0, Qt::UserRole).toString().length() < 2 )
        return;

    int nType = item->data(0, 99 ).toInt();

    connect( viewAct, SIGNAL(triggered(bool)), this, SLOT(viewPathTreeData()));

    menu->addAction( viewAct );

    menu->popup( mPathTree->viewport()->mapToGlobal(pos));
}

void PDFSignerDlg::copyTreeValue()
{
    QTreeWidgetItem* item = mDSSTree->currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( item->data(0, Qt::UserRole ).toString() );

    berApplet->messageBox( tr( "The value has been copied." ), this );
}

void PDFSignerDlg::decodeTreeValue()
{
    QTreeWidgetItem* item = mDSSTree->currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QString strValue = item->data(0, Qt::UserRole ).toString();
    BIN binData = {0,0};

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binData );
    if( JS_PKI_isBER( &binData ) == false )
    {
        berApplet->warningBox( tr( "No avaiable BER" ), this );
        goto end;
    }

    berApplet->decodeTitle( &binData, item->parent()->text(0) );

end :
    JS_BIN_reset( &binData );
}

void PDFSignerDlg::viewTreeValue()
{
    QTreeWidgetItem* item = mDSSTree->currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QString strType = item->parent()->text(0);
    QString strValue = item->data( 0, Qt::UserRole ).toString();
    BIN binData = {0,0};

    JS_BIN_decodeHex( strValue.toStdString().c_str(), &binData );

    if( JS_PKI_isBER( &binData ) == false )
    {
        berApplet->warningBox( tr( "No avaiable BER" ), this );
        goto end;
    }


    if( strType == kDSS_Certs )
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binData, strType );
        certInfo.exec();
    }
    else if( strType == kDSS_CRLs )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &binData, strType );
        crlInfo.exec();
    }
    else if( strType == kDSS_OCSPs )
    {
#if 0
        CertIDDlg certID;
        certID.setResponse2( &binData );
        certID.exec();
#else
        OCSPRspDlg ocspRsp;
        ocspRsp.setResponse( &binData );
        ocspRsp.exec();
#endif
    }
    else if( strType == kDSS )
    {
        CMSInfoDlg cmsInfo;
        cmsInfo.setCMS( &binData, kDocTimeStamp );
        cmsInfo.exec();
    }

end :
    JS_BIN_reset( &binData );
}

void PDFSignerDlg::treePVD()
{
    BINList *pCAList = NULL;
    BINList *pCRLList = NULL;

    BIN binData = {0,0};
    BIN binCMS = {0,0};
    BIN binSigner = {0,0};

    QTreeWidgetItem* item = mDSSTree->currentItem();
    QTreeWidgetItem* dss = nullptr;
    QString strSrcPath = mSrcPathText->text();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    QString strName = item->data(0, 99).toString();
    if( strName.length() <= 0 ) return;

    if( strName == kDSS )
    {
        dss = item;
    }
    else
    {
        if( item->parent() == nullptr || item->parent()->parent() == nullptr )
            return;

        dss = item->parent()->parent();

        int nVRI = item->childCount();
        for( int i = 0; i < nVRI; i++ )
        {
            QTreeWidgetItem* child = dss->child(i);
            if( child->text(0) == kDSS_Cert )
            {
                int nCert = child->childCount();

                for( int k = 0; k < nCert; k++ )
                {
                    QTreeWidgetItem* cert = child->child(k);
                    QString strVal = cert->data(0, Qt::UserRole ).toString();
                    JS_BIN_decodeHex( strVal.toStdString().c_str(), &binData );

                    if( binData.nLen > 0 )
                    {
                        JS_BIN_addList( &pCAList, &binData );
                        JS_BIN_reset( &binData );
                    }
                }
            }
            else if( child->text(0) == kDSS_CRL )
            {
                int nCRL = child->childCount();

                for( int k = 0; k < nCRL; k++ )
                {
                    QTreeWidgetItem* crl = child->child(k);
                    QString strVal = crl->data(0, Qt::UserRole ).toString();
                    JS_BIN_decodeHex( strVal.toStdString().c_str(), &binData );

                    if( binData.nLen > 0 )
                    {
                        JS_BIN_addList( &pCRLList, &binData );
                        JS_BIN_reset( &binData );
                    }
                }
            }
        }
    }

    int nCount = dss->childCount();
    for( int i = 0; i < nCount; i++ )
    {
        QTreeWidgetItem* child = dss->child(i);
        if( child->text(0) == kDSS_Certs )
        {
            int nCert = child->childCount();

            for( int k = 0; k < nCert; k++ )
            {
                QTreeWidgetItem* cert = child->child(k);
                QString strVal = cert->data(0, Qt::UserRole ).toString();
                JS_BIN_decodeHex( strVal.toStdString().c_str(), &binData );

                if( binData.nLen > 0 )
                {
                    JS_BIN_addList( &pCAList, &binData );
                    JS_BIN_reset( &binData );
                }
            }
        }
        else if( child->text(0) == kDSS_CRLs )
        {
            int nCRL = child->childCount();

            for( int k = 0; k < nCRL; k++ )
            {
                QTreeWidgetItem* crl = child->child(k);
                QString strVal = crl->data(0, Qt::UserRole ).toString();
                JS_BIN_decodeHex( strVal.toStdString().c_str(), &binData );

                if( binData.nLen > 0 )
                {
                    JS_BIN_addList( &pCRLList, &binData );
                    JS_BIN_reset( &binData );
                }
            }
        }
    }

    if( pCAList == NULL && pCRLList == NULL )
        return;

    if( strSrcPath.length() > 0 )
    {
        int ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(), NULL, &binCMS );
        if( ret == JSR_OK )
        {
            JS_CMS_getSignedDataSigner( &binCMS, &binSigner );
        }
    }

    CertPVDDlg pvdDlg;
    pvdDlg.setPathList( pCAList, pCRLList );

    if( binSigner.nLen > 0 ) pvdDlg.setTarget( &binSigner );

    pvdDlg.exec();

    if( pCAList ) JS_BIN_resetList( &pCAList );
    if( pCRLList ) JS_BIN_resetList( &pCRLList );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binSigner );
}

void PDFSignerDlg::slotTreeMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QTreeWidgetItem* item = mDSSTree->currentItem();

    if( item == NULL )
    {
        berApplet->warningBox( tr( "No avaiable item" ), this );
        return;
    }

    if( item->parent() == nullptr ) return;

    QString strDSS = item->data(0,99).toString();

    if( strDSS.length() <= 0 )
    {
        if( item->data(0, Qt::UserRole ).toString().length() < 1 ) return;
    }

    QAction *copyValueAct = new QAction( tr( "Copy value" ), this );
    QAction *decodeAct = new QAction( tr( "Decode value" ), this );
    QAction *viewAct = new QAction( tr( "View value" ), this );
    QAction *PVDAct = new QAction( tr( "Path Validation" ), this );

    QString strName = item->parent()->text(0);

    if( strDSS.length() > 0 )
    {
        connect( PVDAct, SIGNAL(triggered(bool)), this, SLOT(treePVD()));
        menu->addAction( PVDAct );
    }
    else
    {
        connect( copyValueAct, SIGNAL(triggered(bool)), this, SLOT(copyTreeValue()));
        connect( decodeAct, SIGNAL(triggered(bool)), this, SLOT(decodeTreeValue()));
        connect( viewAct, SIGNAL(triggered(bool)), this, SLOT(viewTreeValue()));

        menu->addAction( copyValueAct );

        if( strName == kDSS_Certs || strName == kDSS_CRLs || strName == kDSS_OCSPs || strName == kDSS )
        {
            menu->addAction( decodeAct );
            menu->addAction( viewAct );
        }
    }

    menu->popup( mDSSTree->viewport()->mapToGlobal(pos));
}

void PDFSignerDlg::findSrcPath()
{
    int nType = JS_FILE_TYPE_PDF;
    QString strPath = mSrcPathText->text();
    QString strFileName = berApplet->findFile( this, nType, strPath );

    if( strFileName.length() < 1 ) return;

    mSrcPathText->setText( strFileName );
}

void PDFSignerDlg::findDstPath()
{
    int nType = JS_FILE_TYPE_PDF;

    QString strPath = mDstPathText->text();
    QString strFileName = berApplet->findSaveFile( this, nType, strPath );

    if( strFileName.length() < 1 ) return;

    mDstPathText->setText( strFileName );
}

void PDFSignerDlg::clickClearAll()
{
    mSrcPathText->clear();
    mDstPathText->clear();

    clickClearInfo();
    mPasswdText->clear();
}

void PDFSignerDlg::checkDSS()
{
    bool bVal = mDSSCheck->isChecked();
    mVRICheck->setEnabled( bVal );
}

void PDFSignerDlg::checkUseTSP()
{
    bool bVal = mUseTSPCheck->isChecked();
    mTSPBtn->setEnabled( bVal );
}

void PDFSignerDlg::clickTSP()
{
    TimeStampDlg tspDlg;
    tspDlg.exec();
}

void PDFSignerDlg::checkNameSubjectDN()
{
    bool bVal = mUseSubjectDNCheck->isChecked();
    mNameText->setEnabled( !bVal );
}

void PDFSignerDlg::clickGetInfo()
{
    int ret = 0;
    int i = 0;
    QString strSrcPath = mSrcPathText->text();
    JPDFInfo    sInfo;
    QString strPasswd = mPasswdText->text();
    JByteRange sRange;
    JSignLabel  sSignLabel;

    BIN binTSP = {0,0};
    JByteRange sTSPRange;

    JDSSDataList *pDSSList = NULL;
    JNumBINList *pObjList = NULL;
    const BINList *pCurList = NULL;
    int nCount = 0;
    int nNum = 0;

    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sSignLabel, 0x00, sizeof(sSignLabel));
    memset( &sTSPRange, 0x00, sizeof(sTSPRange));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sInfo, &sSignLabel );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get PDF information: %1").arg(JERR(ret)), this);
        return;
    }

    clickClearInfo();

    mInfoTable->setRowCount(0);

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("FileName" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( fileInfo.fileName() ) ));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Version" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sInfo.sVersion ) ));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Pages" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1 page").arg( sInfo.nPage ) ));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Extension Level" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sInfo.nExtLevel ) ));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Encrypted" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sInfo.nEncrypted ? "YES" : "NO" ) ));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight(i,10);
    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("CMS" )));
    mInfoTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sInfo.nCMS ? "YES" : "NO" ) ));
    i++;

    if( sInfo.nCMS == 1 )
    {
        BIN binData = {0,0};
        BIN binHash = {0,0};

        //ret = JS_PDF_findByteRangeFile( strSrcPath.toLocal8Bit().toStdString().c_str(), &sRange );
        ret = JS_PDF_findByteRangeFile(
            strSrcPath.toLocal8Bit().toStdString().c_str(),
            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
            &sRange );
        if( ret == JSR_OK )
        {
            QString strRange = QString( "[ %1 %2 %3 %4 ]" )
            .arg( sRange.nFirstStart)
                .arg( sRange.nFirstLen )
                .arg( sRange.nSecondStart )
                .arg( sRange.nSecondLen );

            mInfoTable->insertRow(i);
            mInfoTable->setRowHeight(i,10);
            mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("ByteRange" )));
            mInfoTable->setItem( i, 1, new QTableWidgetItem( strRange ));
            i++;

            ret = JS_PDF_getDataFile( strSrcPath.toStdString().c_str(), &sRange, &binData );
            if( ret == JSR_OK )
            {
                JS_PKI_genHash( "SHA256", &binData, &binHash );

                mInfoTable->insertRow(i);
                mInfoTable->setRowHeight(i,10);
                mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Hash value" )));
                mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &binHash ) ));
                i++;
            }

            JS_BIN_reset( &binData );
            JS_BIN_reset( &binHash );
        }
    }

    if( sSignLabel.pName )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Name" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( sSignLabel.pName ));
        i++;
    }

    if( sSignLabel.pMakeTime )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("MakeTime" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( sSignLabel.pMakeTime ));
        i++;
    }

    if( sSignLabel.pReason )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Reason" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( sSignLabel.pReason ));
        i++;
    }

    if( sSignLabel.pLocation )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("Location" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( sSignLabel.pLocation ));
        i++;
    }
    if( sSignLabel.pContactInfo )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("ContactInfo" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( sSignLabel.pContactInfo ));
        i++;
    }

    ret = JS_PDF_getDSS_VRI( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            &pDSSList, &pObjList );

    if( ret == JSR_OK )
    {
        QTreeWidgetItem* rootItem = mDSSTree->topLevelItem(0);
        JDSSDataList    *pDSSDataList = NULL;
        JDSSDataList    *pVRIDataList = NULL;
        JDSSData        *pCurData = NULL;

        mVRICombo->clear();

        pDSSDataList = pDSSList;

        if( pDSSDataList )
        {
            pCurData = pDSSDataList->pDSSData;
            QTreeWidgetItem* nameItem = new QTreeWidgetItem;
            nameItem->setText( 0, pCurData->pName );
            nameItem->setIcon( 0, QIcon(":/images/pdf.png" ));
            nameItem->setData( 0, 99, pCurData->pName );

            QTreeWidgetItem* vriItem = nullptr;

            if( pCurData->pCertList )
            {
                nCount = JS_BIN_countList( pCurData->pCertList );
                QTreeWidgetItem* certItem = new QTreeWidgetItem;
                certItem->setText( 0, kDSS_Certs );
                certItem->setIcon(0, QIcon(":/images/cert.png" ));

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pCurData->pCertList );
                    nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_Cert ));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                    QTreeWidgetItem *item = new QTreeWidgetItem;

                    item->setIcon(0, QIcon(":/images/cert.png" ));
                    item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                    item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                    certItem->addChild( item );

                    i++;
                }

                nameItem->addChild( certItem );
            }

            if( pCurData->pCRLList )
            {
                nCount = JS_BIN_countList( pCurData->pCRLList );
                QTreeWidgetItem* crlItem = new QTreeWidgetItem;
                crlItem->setText(0, kDSS_CRLs );
                crlItem->setIcon(0, QIcon(":/images/crl.png" ));

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pCurData->pCRLList );
                    nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_CRL ));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                    QTreeWidgetItem *item = new QTreeWidgetItem;
                    item->setIcon(0, QIcon(":/images/crl.png" ));
                    item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                    item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                    crlItem->addChild( item );

                    i++;
                }

                nameItem->addChild( crlItem );
            }

            if( pCurData->pOCSPList )
            {
                nCount = JS_BIN_countList( pCurData->pOCSPList );

                QTreeWidgetItem* ocspItem = new QTreeWidgetItem;
                ocspItem->setText(0, kDSS_OCSPs );
                ocspItem->setIcon(0, QIcon(":/images/ocsp.png" ));

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pCurData->pOCSPList );
                    nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_OCSP ));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                    QTreeWidgetItem *item = new QTreeWidgetItem;
                    item->setIcon(0, QIcon(":/images/ocsp.png" ));
                    item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                    item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                    ocspItem->addChild( item );
                    i++;
                }

                nameItem->addChild( ocspItem );
            }

            rootItem->addChild( nameItem );
            pVRIDataList = pDSSDataList->pNext;
            pCurData = nullptr;

            if( pVRIDataList )
            {
                pCurData = pVRIDataList->pDSSData;

                if( pCurData )
                {
                    vriItem = new QTreeWidgetItem;
                    vriItem->setText( 0, "VRI" );
                    vriItem->setIcon( 0, QIcon(":/images/pdf.png" ));
                    nameItem->addChild( vriItem );
                }
            }

            while( pCurData )
            {
                mVRICombo->addItem( pCurData->pName );
                QTreeWidgetItem* vriSub = new QTreeWidgetItem;
                vriSub->setText( 0, pCurData->pName );
                vriSub->setIcon( 0, QIcon(":/images/hash.png" ));
                vriSub->setData( 0, 99, pCurData->pName );
                vriItem->addChild( vriSub );

                if( pCurData->pCertList )
                {
                    nCount = JS_BIN_countList( pCurData->pCertList );
                    QTreeWidgetItem* certItem = new QTreeWidgetItem;
                    certItem->setText( 0, kDSS_Cert );
                    certItem->setIcon(0, QIcon(":/images/cert.png" ));

                    for( int k = 0; k < nCount; k++ )
                    {
                        pCurList = JS_BIN_getListAt( k, pCurData->pCertList );
                        nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                        mInfoTable->insertRow(i);
                        mInfoTable->setRowHeight(i,10);
                        mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_Cert ));
                        mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                        QTreeWidgetItem *item = new QTreeWidgetItem;

                        item->setIcon(0, QIcon(":/images/cert.png" ));
                        item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                        item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                        certItem->addChild( item );

                        i++;
                    }

                    vriSub->addChild( certItem );
                }

                if( pCurData->pCRLList )
                {
                    nCount = JS_BIN_countList( pCurData->pCRLList );
                    QTreeWidgetItem* crlItem = new QTreeWidgetItem;
                    crlItem->setText(0, kDSS_CRL );
                    crlItem->setIcon(0, QIcon(":/images/crl.png" ));

                    for( int k = 0; k < nCount; k++ )
                    {
                        pCurList = JS_BIN_getListAt( k, pCurData->pCRLList );
                        nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                        mInfoTable->insertRow(i);
                        mInfoTable->setRowHeight(i,10);
                        mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_CRL ));
                        mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                        QTreeWidgetItem *item = new QTreeWidgetItem;
                        item->setIcon(0, QIcon(":/images/crl.png" ));
                        item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                        item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                        crlItem->addChild( item );

                        i++;
                    }

                    vriSub->addChild( crlItem );
                }

                if( pCurData->pOCSPList )
                {
                    nCount = JS_BIN_countList( pCurData->pOCSPList );

                    QTreeWidgetItem* ocspItem = new QTreeWidgetItem;
                    ocspItem->setText(0, kDSS_OCSP );
                    ocspItem->setIcon(0, QIcon(":/images/ocsp.png" ));

                    for( int k = 0; k < nCount; k++ )
                    {
                        pCurList = JS_BIN_getListAt( k, pCurData->pOCSPList );
                        nNum = JS_PDF_getObjectNum( pObjList, &pCurList->Bin );

                        mInfoTable->insertRow(i);
                        mInfoTable->setRowHeight(i,10);
                        mInfoTable->setItem( i, 0, new QTableWidgetItem( kDSS_OCSP ));
                        mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));

                        QTreeWidgetItem *item = new QTreeWidgetItem;
                        item->setIcon(0, QIcon(":/images/ocsp.png" ));
                        item->setText( 0, QString( "[%1 0 R]" ).arg( nNum ) );
                        item->setData( 0, Qt::UserRole, getHexString( &pCurList->Bin ));
                        ocspItem->addChild( item );
                        i++;
                    }

                    vriSub->addChild( ocspItem );
                }

                if( pVRIDataList->pNext )
                    pCurData = pVRIDataList->pNext->pDSSData;
                else
                    pCurData = nullptr;
            }
        }
    }

    ret = JS_PDF_getDocTimeStamp(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &binTSP, &sTSPRange );

    if( binTSP.nLen > 0 )
    {
        BIN binData = {0,0};
        BIN binHash = {0,0};
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( kDocTimeStamp ));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &binTSP ) ));
        i++;

        QString strTSPRange = QString( "[ %1 %2 %3 %4 ]" )
                                  .arg( sTSPRange.nFirstStart)
                                  .arg( sTSPRange.nFirstLen )
                                  .arg( sTSPRange.nSecondStart )
                                  .arg( sTSPRange.nSecondLen );

        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight(i,10);
        mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("TSP ByteRange" )));
        mInfoTable->setItem( i, 1, new QTableWidgetItem( strTSPRange ));
        i++;

        ret = JS_PDF_getDataFile( strSrcPath.toStdString().c_str(), &sTSPRange, &binData );
        if( ret == JSR_OK )
        {
            JS_PKI_genHash( "SHA256", &binData, &binHash );

            mInfoTable->insertRow(i);
            mInfoTable->setRowHeight(i,10);
            mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("DocTSP Hash" )));
            mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &binHash ) ));
            i++;
        }

        JS_BIN_reset( &binData );
        JS_BIN_reset( &binHash );

        QTreeWidgetItem *item = new QTreeWidgetItem;
        item->setText(0, "DocTimeStamp" );
        item->setData( 0, Qt::UserRole, getHexString( &binTSP ));
        item->setIcon( 0, QIcon(":/images/tsp.png" ));
        mDSSTree->topLevelItem(0)->addChild( item );
    }

    berApplet->messageBox( tr("PDF information import complete"), this );
    mDSSTree->expandAll();
    mTabWidget->setCurrentIndex(0);

    JS_PDF_resetSignLabel( &sSignLabel );
    JS_BIN_reset( &binTSP );

    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );
    if( pObjList ) JS_UTIL_resetNumBINList( &pObjList );
}

void PDFSignerDlg::clickMakePath()
{
    int ret = 0;
    int count = 0;
    BIN binCert = {0,0};
    BINList *pCAList = NULL;
    const BINList *pCurList = NULL;

    bool bOnline = berApplet->settingsMgr()->onlineCA_CRL();
    mPathTree->clear();

    QTreeWidgetItem* pathItem = new QTreeWidgetItem;
    pathItem->setIcon( 0, QIcon(":/images/cert_pvd.png" ));
    pathItem->setText( 0, "Certificate Path" );
    mPathTree->insertTopLevelItem( 0, pathItem );

    CertManDlg certMan;
    certMan.setMode( ManModeSelCert );
    certMan.setTitle( tr( "" ) );
    if( certMan.exec() != QDialog::Accepted )
        goto end;

    certMan.getCert( &binCert );

    JS_BIN_addList( &pCAList, &binCert );

    ret = CertPVDDlg::getStatusDataList( &binCert, bOnline, &pCAList, NULL, NULL );
    count = JS_BIN_countList( pCAList );

    for( int i = 0; i < count; i++ )
    {
        int bSelf = 0;
        JCertInfo sCertInfo;
        BIN binCRL = {0,0};
        BIN binOCSP = {0,0};
        BIN binCA = {0,0};

        pCurList = JS_BIN_getListAt( i, pCAList );

        ret = JS_PKI_getCertInfo2( &pCurList->Bin, &sCertInfo, NULL, &bSelf );
        if( ret != CKR_OK ) continue;

        QTreeWidgetItem *item = new QTreeWidgetItem;
        item->setText( 0, sCertInfo.pSubjectName );
        item->setData(0, Qt::UserRole, getHexString(&pCurList->Bin));

        if( i == 0 )
        {
            item->setIcon( 0, QIcon( ":/images/cert.png" ));
            item->setData(0, 99, PVD_CERT );
        }
        else
        {
            if( bSelf == true )
            {
                item->setIcon( 0, QIcon( ":/images/rca.png" ));
                item->setData(0, 99, PVD_TRUST);
            }
            else
            {
                item->setIcon( 0, QIcon( ":/images/ca.png" ));
                item->setData(0, 99, PVD_UNTRUST);
            }
        }

        CertPVDDlg::getStatusData( &pCurList->Bin, bOnline, &binCA, &binCRL, &binOCSP );

        if( binCRL.nLen > 0 )
        {
            QTreeWidgetItem *crl = new QTreeWidgetItem;
            crl->setText( 0, "CRL" );
            crl->setIcon( 0, QIcon(":/images/crl.png" ));
            crl->setData(0, Qt::UserRole, getHexString(&binCRL ));
            crl->setData(0, 99, PVD_CRL );
            item->addChild( crl );
        }

        if( binOCSP.nLen > 0 )
        {
            QTreeWidgetItem *ocsp = new QTreeWidgetItem;
            ocsp->setText( 0, "OCSP" );
            ocsp->setIcon( 0, QIcon(":/images/ocsp.png" ));
            ocsp->setData(0, Qt::UserRole, getHexString(&binOCSP));
            ocsp->setData(0, 99, PVD_OCSP);
            item->addChild( ocsp );
        }

        pathItem->insertChild( 0, item );

        JS_PKI_resetCertInfo( &sCertInfo );
        JS_BIN_reset( &binCRL );
        JS_BIN_reset( &binOCSP );
    }

    mPathTree->expandAll();
    mTabWidget->setCurrentIndex(2);
end :
    JS_BIN_reset( &binCert );
    if( pCAList ) JS_BIN_resetList( &pCAList );
}

void PDFSignerDlg::clickMakeSign()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();
    time_t now_t = mDateTime->dateTime().toTime_t();

    JByteRange sRange;
    BIN binData = {0,0};
    BIN binUnsigned = {0,0};
    BIN binCMS = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binTSP = {0,0};

//    QString strHash = mHashCombo->currentText();
    QString strPasswd;

    BIN binSignedTSP = {0,0};
    JPDFInfo sInfo;

    JCertInfo sCertInfo;
    JSignLabel sSignLabel;

    char sUTCTime[32];

    QString strTmpPath;
    QString strTmpPath2;

    QString strName = mNameText->text();
    QString strReason = mReasonText->text();
    QString strLocation = mLocationText->text();
    QString strContactInfo = mContactInfoText->text();

    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    memset( &sSignLabel, 0x00, sizeof(sSignLabel));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_signed" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );

        if( mDSSCheck->isChecked() == true )
        {
            strDstPath += "_dss";

            if( mVRICheck->isChecked() == true )
                strDstPath += "_vri";
        }

        if( mDocTimeStampCheck->isChecked() == true )
            strDstPath += "_doc_tsp";

        strDstPath += ".pdf";
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }

        QFile::remove( strDstPath );
    }

    JS_PDF_getUTCTime( now_t, sUTCTime, sizeof(sUTCTime));

    strTmpPath = getTmpFile();
    strTmpPath2 = getTmpFile();

    bool bEncrypted = JS_PDF_isEncryptedFile( strSrcPath.toLocal8Bit().toStdString().c_str());

    if( bEncrypted )
    {
        strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            mPasswdText->setFocus();
            return;
        }
    }

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        strPasswd.toStdString().c_str(),
        &sInfo, NULL );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "Invalid PDF file: %1" ).arg(JERR(ret)), this );
        mSrcPathText->setFocus();
        return;
    }

    if( sInfo.nCMS == 1 )
    {
        berApplet->warningBox( tr("This PDF is already signed"), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = getPriKeyCert( &binPri, &binCert );
    if( ret != 0 ) goto end;

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );


    if( mUseSubjectDNCheck->isChecked() )
        strName = sCertInfo.pSubjectName;

    JS_PDF_setSignLabel( &sSignLabel,
                        sUTCTime,
                        strName.length() > 0 ? strName.toStdString().c_str() : NULL,
                        strReason.length() > 0 ? strReason.toStdString().c_str() : NULL,
                        strLocation.length() > 0 ? strLocation.toStdString().c_str() : NULL,
                        strContactInfo.length() > 0 ? strContactInfo.toStdString().c_str() : NULL );

    ret = JS_PDF_makeUnsigned(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sSignLabel,
        &binUnsigned );

    if( ret != JSR_OK )
    {
        berApplet->warningBox(tr("failed to make unsigned: %1").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_PDF_getByteRange( &binUnsigned, &sRange );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get byte range: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PDF_applyByteRange( &binUnsigned, &sRange );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to apply byte range: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Range [ %1 %2 %3 %4 ]")
                       .arg(sRange.nFirstStart)
                       .arg( sRange.nFirstLen )
                       .arg( sRange.nSecondStart )
                       .arg( sRange.nSecondLen ));

    ret = JS_PDF_getData( &binUnsigned, &sRange, &binData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get body: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "PDF Data[Len:%1]: %2").arg( binData.nLen).arg( getHexString( &binData )));

    ret = JS_PDF_makeCMS( &binData, &binPri, &binCert, &binCMS );

    if( ret == JSR_OK && mUseTSPCheck->isChecked() == true )
    {
        ret = getTSP( &binData, &binTSP );
        if( ret != 0 ) goto end;

        ret = JS_CMS_makeSignedWithTSP( &binCMS, &binTSP, &binSignedTSP );
        if( ret != 0 ) goto end;

        JS_BIN_reset( &binCMS );
        JS_BIN_copy( &binCMS, &binSignedTSP );
    }

#ifdef QT_DEBUG
    ret = JS_PDF_verifyCMS( &binData, &binCert, &binCMS, NULL, NULL, 0, NULL, NULL );
    berApplet->log( QString( "CMS Verify: %1").arg( ret ));
#endif

    berApplet->log( QString( "CMS[Len:%1]: %2").arg( binCMS.nLen).arg( getHexString( &binCMS )));

    ret = JS_PDF_applyContentsCMS( &binUnsigned, &binCMS );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to apply CMS: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_BIN_fileWrite( &binUnsigned, strTmpPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to write file: %1").arg( JERR(ret)), this );
        goto end;
    }

    if( mDSSCheck->isChecked() == true )
    {
        if( mVRICheck->isChecked() == true )
        {
            BIN binCMS_PDF = {0,0};
            JS_BIN_fileRead( strTmpPath.toStdString().c_str(), &binCMS_PDF );

            ret = appendDSS_VRI( strTmpPath, strTmpPath2, &binCMS_PDF, &binCert, mDocTimeStampCheck->isChecked() );
            JS_BIN_reset( &binCMS_PDF );
            if( ret != CKR_OK )
            {
                berApplet->warningBox( tr( "failed to append DSS VRI: %1" ).arg(JERR(ret)), this );
                goto end;
            }
        }
        else
        {
            ret = appendDSS( strTmpPath, strTmpPath2, &binCert, mDocTimeStampCheck->isChecked() );
            if( ret != CKR_OK )
            {
                berApplet->warningBox( tr( "failed to append DSS: %1" ).arg( JERR(ret)), this );
                goto end;
            }
        }
    }

    if( mDocTimeStampCheck->isChecked() == true )
    {
        if( mDSSCheck->isChecked() == false )
        {
            ret = JS_PDF_makeUnsignedTSPDocFile(
                strTmpPath.toStdString().c_str(),
                strTmpPath2.toStdString().c_str() );

            if( ret != 0 ) goto end;
        }

        ret = appendDocTSP( strTmpPath2 );

        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to append DocTSP: %1" ).arg( JERR(ret)), this );
            goto end;
        }
    }

    if( mDSSCheck->isChecked() == true || mDocTimeStampCheck->isChecked() == true )
    {
        QFile dstFile( strTmpPath2 );
        dstFile.copy( strDstPath );
    }
    else
    {
        QFile dstFile( strTmpPath );
        dstFile.copy( strDstPath );
    }

    berApplet->messageBox( tr("PDF signing was successful"), this );

end :
    if( QFile::exists( strTmpPath ) ) QFile::remove( strTmpPath );
    if( QFile::exists( strTmpPath2 ) )QFile::remove( strTmpPath2 );

    JS_BIN_reset( &binData );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binTSP );
    JS_BIN_reset( &binSignedTSP );
    JS_BIN_reset( &binUnsigned );
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_PDF_resetSignLabel( &sSignLabel );
}

void PDFSignerDlg::clickVerifySign()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();
    BIN binPDF = {0,0};
    BIN binCert = {0,0};
    BIN binCMS = {0,0};
    BIN binData = {0,0};
    BIN binOut = {0,0};
    BIN binSigner = {0,0};

    JByteRange  sRange;
    JPDFInfo    sInfo;

    int nVerifyChain = 0;
    JSignLabel  sSignLabel;

    char sResMsg[1024];

    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sSignLabel, 0x00, sizeof(sSignLabel));
    memset( sResMsg, 0x00, sizeof(sResMsg));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &sInfo, &sSignLabel );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "Invalid PDF file: %1" ).arg(JERR(ret)), this );
        mSrcPathText->setFocus();
        return;
    }

    if( sInfo.nCMS == 0 )
    {
        berApplet->warningBox( tr( "This PDF is not signed" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( mCertCheck->isChecked() == true )
    {
        ret = getCert( &binCert );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get the public key: %1" ).arg(ret), this );
            goto end;
        }
    }

    ret = JS_PDF_readPlain(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &binPDF );

    //   ret = JS_PDF_getByteRange( &binPDF, &sRange );
    ret = JS_PDF_findByteRange(
        &binPDF,
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sRange );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get byte range: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify Range [ %1 %2 %3 %4 ]")
                       .arg(sRange.nFirstStart)
                       .arg( sRange.nFirstLen )
                       .arg( sRange.nSecondStart )
                       .arg( sRange.nSecondLen ));

    //    ret = JS_PDF_getCMS( &binPDF, &binCMS );
    ret = JS_PDF_getContents( &binPDF,
                             strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                             &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get CMS: %1").arg(JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify CMS[Len:%1]: %2").arg(binCMS.nLen).arg( getHexString( &binCMS )));

    ret = JS_PDF_getData( &binPDF, &sRange, &binData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get body: %1").arg(JERR(ret)), this );
        goto end;
    }

#if defined(QT_DEBUG)
    {
        QString strTmpData = QString( "%1/%2" ).arg( fileInfo.path()).arg( fileInfo.baseName() );
        strTmpData += "_data.bin";

        QString strTmpCMS = QString( "%1/%2" ).arg( fileInfo.path()).arg( fileInfo.baseName() );
        strTmpCMS += "_cms.bin";

        JS_BIN_fileWrite( &binData, strTmpData.toLocal8Bit().toStdString().c_str() );
        JS_BIN_fileWrite( &binCMS, strTmpCMS.toLocal8Bit().toStdString().c_str() );
    }
#endif

    if( mVerifyChainCheck->isChecked() )
        nVerifyChain = 1;
    else
        nVerifyChain = 0;

    berApplet->log( QString( "Verify PDF Data[Len:%1]: %2").arg(binData.nLen).arg( getHexString( &binData )));

    ret = JS_PDF_verifyCMS(
        &binData,
        &binCert,
        &binCMS,
        mCAListCheck->isChecked() ? berApplet->settingsMgr()->CACertPath().toLocal8Bit().toStdString().c_str() : NULL,
        mTrustListCheck->isChecked() ? berApplet->settingsMgr()->trustCertPath().toLocal8Bit().toStdString().c_str() : NULL,
        nVerifyChain, &binSigner, sResMsg );


    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr( "failed to verify CMS: %1(%2)").arg( JERR(ret)).arg(sResMsg), this );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPDF );
    JS_BIN_reset( &binSigner );
    JS_PDF_resetSignLabel( &sSignLabel );
}

void PDFSignerDlg::clickClearInfo()
{
    mInfoTable->setRowCount(0);
    mDSSTree->clear();

    QTreeWidgetItem* tItem = new QTreeWidgetItem;
    tItem->setText( 0, kDSS );

    mDSSTree->insertTopLevelItem( 0, tItem );
}

void PDFSignerDlg::clickEncrypt()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();

    JPDFInfo sInfo;

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strPasswd = mPasswdText->text();
    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password"), this );
        mPasswdText->setFocus();
        return;
    }

    ret = JS_PDF_getInfoFile( strSrcPath.toLocal8Bit().toStdString().c_str(), NULL, &sInfo, NULL );
    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr(" failed to get PDF information: %1").arg( JERR(ret)), this );
        return;
    }

    if( sInfo.nEncrypted )
    {
        berApplet->warningBox( tr("It's already encrypted"), this );
        return;
    }

    if( sInfo.nCMS )
    {
        bool bVal = berApplet->yesOrNoBox( tr("There is an electronic signature. Encryption will result in a signature mismatch. Would you like to continue?"), this, false );
        if( bVal == false ) return;
    }

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_enc.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }
    }

    ret = JS_PDF_encryptFile( strSrcPath.toLocal8Bit().toStdString().c_str(),
                             strPasswd.toStdString().c_str(),
                             strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "PDF encryption successful"), this );
    }
    else
    {
        berApplet->warningBox( tr("PDF encryption failed: %1").arg(JERR(ret)), this );
    }

    return;
}

void PDFSignerDlg::clickDecrypt()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();
    JPDFInfo sInfo;

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strPasswd = mPasswdText->text();
    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password"), this );
        mPasswdText->setFocus();
        return;
    }

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_dec.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }
    }

    ret = JS_PDF_getInfoFile( strSrcPath.toLocal8Bit().toStdString().c_str(), NULL, &sInfo, NULL );
    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr(" failed to get PDF information: %1").arg( JERR(ret)), this );
        return;
    }

    if( sInfo.nEncrypted == false )
    {
        berApplet->warningBox( tr("It is not encrypted"), this );
        return;
    }

    if( sInfo.nCMS )
    {
        bool bVal = berApplet->yesOrNoBox( tr("There is an electronic signature. Decryption will result in a signature mismatch. Would you like to continue?"), this, false );
        if( bVal == false ) return;
    }

    ret = JS_PDF_decryptFile( strSrcPath.toLocal8Bit().toStdString().c_str(),
                             strPasswd.toStdString().c_str(),
                             strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "PDF decryption successful"), this );
    }
    else
    {
        berApplet->warningBox( tr("PDF decryption failed: %1").arg(JERR(ret)), this );
    }

    return;
}

#if 1
void PDFSignerDlg::clickViewSigner()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    BIN binCMS = {0,0};
    BIN binSigner = {0,0};

    CertInfoDlg certInfo;
    QString strPasswd = mPasswdText->text();

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    //    ret = JS_PDF_getCMSFile( strSrcPath.toLocal8Bit().toStdString().c_str(), &binCMS );
    ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("Failed to retrieve CMS information: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_CMS_getSignedDataSigner( &binCMS, &binSigner );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get CMS signer: %1").arg(JERR(ret)), this );
        goto end;
    }

    certInfo.setCertBIN( &binSigner );
    certInfo.exec();

end :
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binSigner );
}
#endif

void PDFSignerDlg::clickViewCMS()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    BIN binCMS = {0,0};

    CMSInfoDlg cmsInfo;
    QString strPasswd = mPasswdText->text();

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    //    ret = JS_PDF_getCMSFile( strSrcPath.toLocal8Bit().toStdString().c_str(), &binCMS );
    ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("Failed to retrieve CMS information: %1").arg( JERR(ret)), this );
        goto end;
    }

    cmsInfo.setCMS( &binCMS );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binCMS );
}

void PDFSignerDlg::clickExportCMS()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();
    BIN binCMS = {0,0};

    ExportDlg exportDlg;

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    //    ret = JS_PDF_getCMSFile( strSrcPath.toLocal8Bit().toStdString().c_str(), &binCMS );
    ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("Failed to retrieve CMS information: %1").arg( JERR(ret)), this );
        goto end;
    }

    exportDlg.setPKCS7( &binCMS );
    exportDlg.setName( fileInfo.baseName() );
    exportDlg.exec();

end :
    JS_BIN_reset( &binCMS );
}

int PDFSignerDlg::appendDSS( const QString strSrcPath,
              const QString strDstPath,
              const BIN *pCert, int bDocTSP )
{
    int ret = 0;
    BIN binCRL = {0,0};

    BINList *pCertList = NULL;
    BINList *pCRLList = NULL;
    BINList *pOCSPList = NULL;

    JS_BIN_addList( &pCertList, pCert );

    getDSSList( pCert, &pCertList, &pCRLList, &pOCSPList );

    ret = JS_PDF_appendDSS( strSrcPath.toStdString().c_str(),
                           strDstPath.toStdString().c_str(),
                           mCompressCheck->isChecked(),
                           bDocTSP,
                           pCertList, pCRLList, pOCSPList );

end :
    if( pCertList ) JS_BIN_resetList( &pCertList );
    if( pCRLList ) JS_BIN_resetList( &pCRLList );
    if( pOCSPList ) JS_BIN_resetList( &pOCSPList );

    JS_BIN_reset( &binCRL );

    return ret;
}

int PDFSignerDlg::appendDSS_VRI( const QString strSrcPath,
                  const QString strDstPath,
                  const BIN *pCMS_PDF,
                  const BIN *pCert, int bDocTSP )
{
    int ret = 0;

    JDSSDataList *pDSSList = NULL;
    JDSSData sDSSData;
    JDSSData sVRIData;

    BIN binHash = {0,0};
    BIN binCA = {0,0};
    BIN binCRL = {0,0};
    BIN binOCSP = {0,0};


    memset( &sDSSData, 0x00, sizeof(sDSSData));
    memset( &sVRIData, 0x00, sizeof(sVRIData));

    JS_PDF_setDSSDataName( &sDSSData, "DSS" );

    getDSSList( pCert, &sDSSData.pCertList, &sDSSData.pCRLList, &sDSSData.pOCSPList );
    JS_BIN_addList( &sDSSData.pCertList, pCert );

    JS_PKI_genHash( "SHA256", pCMS_PDF, &binHash );

    JS_PDF_setDSSDataName( &sVRIData, getHexString( &binHash ).toStdString().c_str() );

    ret = getDSS( pCert, &binCA, &binCRL, &binOCSP );
    if( ret == JSR_OK )
    {
        JS_PDF_setDSSDataCert( &sVRIData, pCert );
        if( binCRL.nLen > 0 )
            JS_PDF_setDSSDataCRL( &sVRIData, &binCRL );

        if( binOCSP.nLen > 0 )
            JS_PDF_setDSSDataOCSP( &sVRIData, &binOCSP );
    }


    JS_PDF_addDSSDataList( &pDSSList, &sDSSData );
    JS_PDF_addDSSDataList( &pDSSList, &sVRIData );

    ret = JS_PDF_appendDSS_VRI( strSrcPath.toStdString().c_str(),
                               strDstPath.toStdString().c_str(),
                               mCompressCheck->isChecked(),
                               bDocTSP,
                               pDSSList );

end :
    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );

    JS_PDF_resetDSSData( &sDSSData );
    JS_PDF_resetDSSData( &sVRIData );

    JS_BIN_reset( &binHash );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binOCSP );

    return ret;
}

void PDFSignerDlg::clickAddDSS()
{
    int ret = 0;

    BIN binCert = {0,0};

    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();
    QString strPasswd = mPasswdText->text();

    JDSSDataList *pDSSList = NULL;
    JNumBINList *pObjList = NULL;

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_dss.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }
    }

    ret = JS_PDF_getDSS_VRI( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            &pDSSList, &pObjList );
    if( ret == JSR_OK )
    {
        berApplet->warningBox( tr("The DSS value already exists."), this );
        goto end;
    }


    ret = getCert( &binCert );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get the certificate: %1" ).arg(ret), this );
        goto end;
    }

    ret = appendDSS( strSrcPath, strDstPath, &binCert, 0 );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DSS added successfully" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to add DSS: %1").arg(JERR(ret)), this );
    }

end :
    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );
    if( pObjList ) JS_UTIL_resetNumBINList( &pObjList );
    JS_BIN_reset( &binCert );
}

void PDFSignerDlg::clickAddDSS_VRI()
{
    int ret = 0;

    BIN binCert = {0,0};
    BIN binCMS_PDF = {0,0};

    JDSSDataList *pDSSList = NULL;
    JNumBINList *pObjList = NULL;

    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();
    QString strPasswd = mPasswdText->text();

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_dss_vri.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }
    }

    ret = JS_PDF_getDSS_VRI( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            &pDSSList, &pObjList );
    if( ret == JSR_OK )
    {
        berApplet->warningBox( tr("The DSS value already exists."), this );
        goto end;
    }

    ret = getCert( &binCert );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get the certificate: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_PDF_getContentsFile(
        strDstPath.toStdString().c_str(),
        NULL,
        &binCMS_PDF );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get the CMS contents: %1" ).arg(JERR(ret)), this );
        goto end;
    }


    ret = appendDSS_VRI( strSrcPath, strDstPath, &binCMS_PDF, &binCert, 0 );

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "DSS added successfully" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to add DSS: %1").arg(JERR(ret)), this );
    }

end :
    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );
    if( pObjList ) JS_UTIL_resetNumBINList( &pObjList );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCMS_PDF );
}

int PDFSignerDlg::appendDocTSP( const QString strUnsignedPath )
{
    int ret = 0;

    BIN binData = {0,0};
    BIN binTSP = {0,0};

    JByteRange sRange;

    memset( &sRange, 0x00, sizeof(sRange));

    // Need To DocTSP ByteRange

    ret = JS_PDF_getDocTSPByteRangeFile( strUnsignedPath.toStdString().c_str(), &sRange );
    if( ret != 0 ) goto end;

    ret = JS_PDF_applyDocTSPByteRangeFile( strUnsignedPath.toStdString().c_str(), &sRange );
    if( ret != 0 ) goto end;

    ret = JS_PDF_getDataFile( strUnsignedPath.toStdString().c_str(), &sRange, &binData );
    if( ret != 0 ) goto end;

    ret = getTSP( &binData, &binTSP );
    if( ret != 0 ) goto end;

    ret = JS_PDF_applyContentsDocTSPFile( strUnsignedPath.toStdString().c_str(), &binTSP );
    if( ret != JSR_OK ) goto end;

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTSP );

    return ret;
}

void PDFSignerDlg::clickAddDocTSP()
{
    int ret = 0;
    int bSetOnly = 0;

    BIN binData = {0,0};
    BIN binTSP = {0,0};

    JByteRange sRange;

    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();

    memset( &sRange, 0x00, sizeof(sRange));

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_tsp.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    QFileInfo dstInfo( strDstPath );
    if( dstInfo.exists() )
    {
        bool bVal = berApplet->yesOrNoBox( tr("The target file already exists. Do you want to continue?"), this, false );
        if( bVal == false )
        {
            mDstPathText->setFocus();
            return;
        }
    }

    ret = JS_PDF_makeUnsignedTSPDocFile(
        strSrcPath.toStdString().c_str(),
        strDstPath.toStdString().c_str() );

    if( ret != 0 ) goto end;

    ret = appendDocTSP( strDstPath );

    if( ret != JSR_OK ) goto end;

    berApplet->messageBox( tr("append DocTSP successfully"), this );

end :
    if( ret != JSR_OK )
    {
        QFile dstFile( strDstPath );
        dstFile.remove();
        berApplet->warningBox( tr( "failed to append DocTSP: %1").arg(JERR(ret)), this );
    }

    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTSP );
}

void PDFSignerDlg::clickViewDocTSP()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();

    JByteRange sRange;

    BIN binCMS = {0,0};

    ExportDlg exportDlg;
    CMSInfoDlg cmsInfo;
    int nFlag = -1;

    memset( &sRange, 0x00, sizeof(sRange));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getDocTimeStamp( strSrcPath.toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS, &sRange );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get DocTimeStamp: %1").arg(JERR(ret)), this );
        goto end;
    }

    cmsInfo.setCMS( &binCMS, kDocTimeStamp );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binCMS );
}

void PDFSignerDlg::clickVerifyDocTSP()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();

    JByteRange sRange;

    BIN binCMS = {0,0};
    BIN binData = {0,0};
    BIN binTST = {0,0};

    ExportDlg exportDlg;
    int nFlag = -1;
    char sResMsg[1024];
    JTSTInfo sTSTInfo;

    time_t check_t = time(NULL);

    memset( &sRange, 0x00, sizeof(sRange));
    memset( sResMsg, 0x00, sizeof(sResMsg));
    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getDocTimeStamp( strSrcPath.toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS, &sRange );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get DocTimeStamp: %1").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_TSP_getTST( &binCMS, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST: %1" ).arg(JERR(ret)), this);
        goto end;
    }

    ret = JS_TSP_decodeTSTInfo( &binTST, &sTSTInfo );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST information: %1").arg(JERR(ret)), this );
        goto end;
    }

    check_t = sTSTInfo.tGenTime;

    ret = JS_CMS_verifySignedData( &binCMS, NULL, NULL, nFlag, check_t, NULL, NULL, &binData, sResMsg );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr( "DocTimeStamp Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to verify DocTimeStamp: %1(%2)" ).arg(JERR(ret)).arg(sResMsg), this );
    }

end :
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
    JS_TSP_resetTSTInfo( &sTSTInfo );
}

void PDFSignerDlg::clickViewDocTSP_TST()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();

    JByteRange sRange;

    BIN binCMS = {0,0};
    BIN binTST = {0,0};

    ExportDlg exportDlg;
    TSTInfoDlg tstInfo;
    int nFlag = -1;

    memset( &sRange, 0x00, sizeof(sRange));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getDocTimeStamp( strSrcPath.toStdString().c_str(),
                                 strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                 &binCMS, &sRange );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get DocTimeStamp: %1").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_TSP_getTST( &binCMS, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST: %1").arg(JERR(ret)), this );
        goto end;
    }

    tstInfo.setTST( &binTST );
    tstInfo.exec();

end :
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binTST );
}

void PDFSignerDlg::clickVerifyDSS()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();
    BIN binPDF = {0,0};
    BIN binCert = {0,0};
    BIN binCMS = {0,0};
    BIN binData = {0,0};
    BIN binOut = {0,0};
    BIN binSigner = {0,0};
    BIN binTSP = {0,0};
    BIN binTST = {0,0};

    JByteRange  sRange;
    JPDFInfo    sInfo;
    JDSSDataList *pDSSList = NULL;
    JNumBINList *pObjList = NULL;
    JTSTInfo     sTSTInfo;

    JSignLabel  sSignLabel;
    char sResMsg[1024];

    JCMSSigned sSigned;
    JSignerInfoList *pInfoList = NULL;

    time_t check_t = time(NULL);

    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sSignLabel, 0x00, sizeof(sSignLabel));
    memset( sResMsg, 0x00, sizeof(sResMsg));
    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));
    memset( &sSigned, 0x00, sizeof(sSigned));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &sInfo, &sSignLabel );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "Invalid PDF file: %1" ).arg(JERR(ret)), this );
        mSrcPathText->setFocus();
        return;
    }

    if( sInfo.nCMS == 0 )
    {
        berApplet->warningBox( tr( "This PDF is not signed" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( mCertCheck->isChecked() == true )
    {
        ret = getCert( &binCert );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get the public key: %1" ).arg(ret), this );
            goto end;
        }
    }

    ret = JS_PDF_readPlain(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &binPDF );

    //   ret = JS_PDF_getByteRange( &binPDF, &sRange );
    ret = JS_PDF_findByteRange(
        &binPDF,
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sRange );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get byte range: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify Range [ %1 %2 %3 %4 ]")
                       .arg(sRange.nFirstStart)
                       .arg( sRange.nFirstLen )
                       .arg( sRange.nSecondStart )
                       .arg( sRange.nSecondLen ));

    //    ret = JS_PDF_getCMS( &binPDF, &binCMS );
    ret = JS_PDF_getContents( &binPDF,
                             strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                             &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get CMS: %1").arg(JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify CMS[Len:%1]: %2").arg(binCMS.nLen).arg( getHexString( &binCMS )));

    ret = JS_CMS_getSignedData( &binCMS, &sSigned, &pInfoList, &binTSP );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TSP: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_TSP_getTST( &binTSP, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST: %1" ).arg(JERR(ret)), this);
        goto end;
    }

    ret = JS_TSP_decodeTSTInfo( &binTST, &sTSTInfo );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST information: %1").arg(JERR(ret)), this );
        goto end;
    }

    check_t = sTSTInfo.tGenTime;

    ret = JS_PDF_getData( &binPDF, &sRange, &binData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get body: %1").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_CMS_verifySignedData( &binTSP, NULL, NULL, -1, check_t, NULL, NULL, NULL, sResMsg );
    if( ret != JSR_VERIFY )
    {
        berApplet->warningBox( tr( "failed to verify TSP: %1(%2)" ).arg(JERR(ret)).arg(sResMsg), this );
        goto end;
    }

    ret = JS_PDF_getDSS_VRI( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            &pDSSList, &pObjList );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get DSS: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify PDF Data[Len:%1]: %2").arg(binData.nLen).arg( getHexString( &binData )));

    if( binCert.nLen <= 0 ) JS_CMS_getSignedDataSigner( &binCMS, &binCert );

#if defined(QT_DEBUG)
    {
        QString strTmpData = QString( "%1/%2" ).arg( fileInfo.path()).arg( fileInfo.baseName() );
        strTmpData += "_dss_data.bin";

        QString strTmpCMS = QString( "%1/%2" ).arg( fileInfo.path()).arg( fileInfo.baseName() );
        strTmpCMS += "_dss_cms.bin";

        JS_BIN_fileWrite( &binData, strTmpData.toLocal8Bit().toStdString().c_str() );
        JS_BIN_fileWrite( &binCMS, strTmpCMS.toLocal8Bit().toStdString().c_str() );
    }
#endif

    ret = JS_PDF_verifyCMS_DSS(
        &binData,
        &binCert,
        &binCMS,
        pDSSList->pDSSData->pCertList,
        pDSSList->pDSSData->pCRLList,
        pDSSList->pDSSData->pOCSPList,
        check_t,
        &binSigner, sResMsg );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr("Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to verify CMS: %1(%2)").arg( JERR(ret)).arg(sResMsg), this );
    }

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPDF );
    JS_BIN_reset( &binSigner );
    JS_BIN_reset( &binTSP );
    JS_BIN_reset( &binTST );
    JS_TSP_resetTSTInfo( &sTSTInfo );
    JS_PDF_resetSignLabel( &sSignLabel );
    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );
    if( pObjList ) JS_UTIL_resetNumBINList( &pObjList );
    JS_CMS_resetSigned( &sSigned );
    if( pInfoList ) JS_CMS_resetSignerInfoList( &pInfoList );
}

void PDFSignerDlg::clickVerifyDSS_VRI()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();
    QString strVRI = mVRICombo->currentText();

    BIN binPDF = {0,0};
    BIN binCert = {0,0};
    BIN binCMS = {0,0};
    BIN binData = {0,0};
    BIN binOut = {0,0};
    BIN binSigner = {0,0};
    BIN binTSP = {0,0};
    BIN binTST = {0,0};

    JByteRange  sRange;
    JPDFInfo    sInfo;

    JSignLabel  sSignLabel;

    JDSSDataList *pDSSList = NULL;
    JDSSDataList *pCurList = NULL;
    JNumBINList *pObjList = NULL;
    BINList *pBINList = NULL;

    char sResMsg[1024];

    JTSTInfo    sTSTInfo;
    JCMSSigned  sSigned;
    JSignerInfoList *pInfoList = NULL;

    time_t check_t = time(NULL);

    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sSignLabel, 0x00, sizeof(sSignLabel));
    memset( sResMsg, 0x00, sizeof(sResMsg));
    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));
    memset( &sSigned, 0x00, sizeof(sSigned));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( strVRI.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a VRI" ), this );
        mVRICombo->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &sInfo, &sSignLabel );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "Invalid PDF file: %1" ).arg(JERR(ret)), this );
        mSrcPathText->setFocus();
        return;
    }

    if( sInfo.nCMS == 0 )
    {
        berApplet->warningBox( tr( "This PDF is not signed" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( mCertCheck->isChecked() == true )
    {
        ret = getCert( &binCert );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get the public key: %1" ).arg(ret), this );
            goto end;
        }
    }

    ret = JS_PDF_readPlain(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        NULL,
        &binPDF );

    //   ret = JS_PDF_getByteRange( &binPDF, &sRange );
    ret = JS_PDF_findByteRange(
        &binPDF,
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sRange );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get byte range: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify Range [ %1 %2 %3 %4 ]")
                       .arg(sRange.nFirstStart)
                       .arg( sRange.nFirstLen )
                       .arg( sRange.nSecondStart )
                       .arg( sRange.nSecondLen ));

    //    ret = JS_PDF_getCMS( &binPDF, &binCMS );
    ret = JS_PDF_getContents( &binPDF,
                             strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                             &binCMS );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get CMS: %1").arg(JERR(ret)), this );
        goto end;
    }

    berApplet->log( QString( "Verify CMS[Len:%1]: %2").arg(binCMS.nLen).arg( getHexString( &binCMS )));

    ret = JS_CMS_getSignedData( &binCMS, &sSigned, &pInfoList, &binTSP );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TSP: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_TSP_getTST( &binTSP, &binTST );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST: %1" ).arg(JERR(ret)), this);
        goto end;
    }

    ret = JS_TSP_decodeTSTInfo( &binTST, &sTSTInfo );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get TST information: %1").arg(JERR(ret)), this );
        goto end;
    }

    check_t = sTSTInfo.tGenTime;

    ret = JS_PDF_getData( &binPDF, &sRange, &binData );
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get body: %1").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_CMS_verifySignedData( &binTSP, NULL, NULL, -1, check_t, NULL, NULL, NULL, sResMsg );
    if( ret != JSR_VERIFY )
    {
        berApplet->warningBox( tr( "failed to verify TSP: %1(%2)" ).arg(JERR(ret)).arg(sResMsg), this );
        goto end;
    }

    ret = JS_PDF_getDSS_VRI( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            &pDSSList, &pObjList );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get DSS: %1" ).arg(JERR(ret)), this );
        goto end;
    }

    pCurList = pDSSList;

    while( pCurList )
    {
        if( pCurList->pDSSData->pName == strVRI )
        {
            break;
        }

        pCurList = pCurList->pNext;
    }

    if( pCurList == NULL )
    {
        berApplet->warningBox( tr( "There is no corresponding VRI value."), this );
        goto end;
    }

    pBINList = pCurList->pDSSData->pCertList;

    while( pBINList )
    {
        JS_BIN_addList( &pDSSList->pDSSData->pCertList, &pBINList->Bin );
        pBINList = pBINList->pNext;
    }

    pBINList = pCurList->pDSSData->pCRLList;

    while( pBINList )
    {
        JS_BIN_addList( &pDSSList->pDSSData->pCRLList, &pBINList->Bin );
        pBINList = pBINList->pNext;
    }

    pBINList = pCurList->pDSSData->pOCSPList;

    while( pBINList )
    {
        JS_BIN_addList( &pDSSList->pDSSData->pOCSPList, &pBINList->Bin );
        pBINList = pBINList->pNext;
    }

    berApplet->log( QString( "Verify PDF Data[Len:%1]: %2").arg(binData.nLen).arg( getHexString( &binData )));

    ret = JS_PDF_verifyCMS_DSS(
        &binData,
        &binCert,
        &binCMS,
        pDSSList->pDSSData->pCertList,
        pDSSList->pDSSData->pCRLList,
        pDSSList->pDSSData->pOCSPList,
        check_t,
        &binSigner, sResMsg );

    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr( "failed to verify CMS: %1(%2)").arg( JERR(ret)).arg(sResMsg), this );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPDF );
    JS_BIN_reset( &binSigner );
    JS_PDF_resetSignLabel( &sSignLabel );

    if( pDSSList ) JS_PDF_resetDSSDataList( &pDSSList );
    if( pObjList ) JS_UTIL_resetNumBINList( &pObjList );
}

void PDFSignerDlg::clickExportByteRange()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();

    JByteRange sRange;

    BIN binPDF = {0,0};

    ExportDlg exportDlg;

    memset( &sRange, 0x00, sizeof(sRange));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_findByteRangeFile( strSrcPath.toStdString().c_str(),
                                   strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                   &sRange );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("Failed to retrieve range: %1").arg( JERR(ret)), this );
        goto end;
    }

    JS_PDF_getDataFile( strSrcPath.toStdString().c_str(), &sRange, &binPDF );

    exportDlg.setBIN( &binPDF );
    exportDlg.setName( fileInfo.baseName() );
    exportDlg.exec();

end :
    JS_BIN_reset( &binPDF );
}

void PDFSignerDlg::clickExportDocTSPByteRange()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    QString strPasswd = mPasswdText->text();
    JByteRange sRange;

    BIN binPDF = {0,0};

    ExportDlg exportDlg;

    memset( &sRange, 0x00, sizeof(sRange));

    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QFileInfo fileInfo( strSrcPath );
    if( fileInfo.exists() == false )
    {
        berApplet->warningBox( tr( "There is no file" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = JS_PDF_getDocTimeStampRange( strSrcPath.toStdString().c_str(),
                                      strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                                      &sRange );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("Failed to retrieve DocTimeStamp range: %1").arg( JERR(ret)), this );
        goto end;
    }

    JS_PDF_getDataFile( strSrcPath.toStdString().c_str(), &sRange, &binPDF );

    exportDlg.setBIN( &binPDF );
    exportDlg.setName( fileInfo.baseName() );
    exportDlg.exec();

end :
    JS_BIN_reset( &binPDF );
}

void PDFSignerDlg::clickDstPathUp()
{
    QString strDstPath = mDstPathText->text();
    mDstPathText->clear();

    mSrcPathText->setText( strDstPath );
}

int PDFSignerDlg::getDSS( const BIN *pCert, BIN *pCA, BIN *pCRL, BIN *pOCSP )
{
    int ret = 0;
    bool bOnline = berApplet->settingsMgr()->getOnlineCA_CRL();

    ret = CertPVDDlg::getStatusData( pCert, bOnline, pCA, pCRL, pOCSP );
    return ret;
}

int PDFSignerDlg::getDSSList( const BIN *pCert, BINList **ppCertList, BINList **ppCRLList, BINList **ppOCSPList )
{
    int ret = 0;

    bool bOnline = berApplet->settingsMgr()->getOnlineCA_CRL();

    ret = CertPVDDlg::getStatusDataList( pCert, bOnline, ppCertList, ppCRLList, ppOCSPList );
    return ret;
}

#endif
