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

    connect( mUseTSPCheck, SIGNAL(clicked()), this, SLOT(checkUseTSP()));
    connect( mTSPBtn, SIGNAL(clicked()), this, SLOT(clickTSP()));

    connect( mUseSubjectDNCheck, SIGNAL(clicked()), this, SLOT(checkNameSubjectDN()));
    connect( mGetInfoBtn, SIGNAL(clicked()), this, SLOT(clickGetInfo()));
    connect( mInfoClearBtn, SIGNAL(clicked()), this, SLOT(clickClearInfo()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mSignCheck, SIGNAL(clicked()), this, SLOT(checkSign()));
    connect( mEncryptCheck, SIGNAL(clicked()), this, SLOT(checkEnc()));
    connect( mViewCMSBtn, SIGNAL(clicked()), this, SLOT(clickViewCMS()));
    connect( mExportCMSBtn, SIGNAL(clicked()), this, SLOT(clickExportCMS()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
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

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(sHeaders.size());
    mInfoTable->setHorizontalHeaderLabels( sHeaders );
    mInfoTable->verticalHeader()->setVisible(false);
    mInfoTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mInfoTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mNameText->setPlaceholderText( tr("String value" ));
    mReasonText->setPlaceholderText( tr( "String value" ));
    mLocationText->setPlaceholderText( tr("String value" ));
    mContactInfoText->setPlaceholderText( tr("String value" ));
}

void PDFSignerDlg::initialize()
{
    QDateTime dateTime = QDateTime::currentDateTime();
    mDateTime->setDateTime( dateTime );
    mSignCheck->setChecked(true);
    checkSign();
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

    ret = JS_TSP_decodeResponse( &binRsp, pTSP, &binTST );

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

void PDFSignerDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *copyValueAct = new QAction( tr( "Copy value" ), this );

    connect( copyValueAct, SIGNAL(triggered(bool)), this, SLOT(copyValue()));

    menu->addAction( copyValueAct );

    menu->popup( mInfoTable->viewport()->mapToGlobal(pos));
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

void PDFSignerDlg::checkSign()
{
    mMakeBtn->setText( tr("Make") );
    mVerifyBtn->setText( tr("Verify" ));
}

void PDFSignerDlg::checkEnc()
{
    mMakeBtn->setText( tr("Encrypt") );
    mVerifyBtn->setText( tr("Decrypt" ));
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

    memset( &sInfo, 0x00, sizeof(sInfo));
    memset( &sRange, 0x00, sizeof(sRange));
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

    ret = JS_PDF_getInfoFile(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
        &sInfo, &sSignLabel );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get PDF information: %1").arg(JERR(ret)), this);
        return;
    }



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
        BINList *pCertList = NULL;
        BINList *pCRLList = NULL;
        BINList *pOCSPList = NULL;
        const BINList *pCurList = NULL;
        int nCount = 0;

        BIN binTSP = {0,0};

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
        }

        ret = JS_PDF_getDSS( strSrcPath.toLocal8Bit().toStdString().c_str(),
                            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
                            NULL,
                            &pCertList, &pCRLList, &pOCSPList );

        if( ret == JSR_OK )
        {
            if( pCertList )
            {
                nCount = JS_BIN_countList( pCertList );

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pCertList );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("DSS Cert" )));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));
                    i++;
                }
            }

            if( pCRLList )
            {
                nCount = JS_BIN_countList( pCRLList );

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pCRLList );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("DSS OCSP" )));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));
                    i++;
                }
            }

            if( pOCSPList )
            {
                nCount = JS_BIN_countList( pOCSPList );

                for( int k = 0; k < nCount; k++ )
                {
                    pCurList = JS_BIN_getListAt( k, pOCSPList );

                    mInfoTable->insertRow(i);
                    mInfoTable->setRowHeight(i,10);
                    mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("DSS CRL" )));
                    mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &pCurList->Bin ) ));
                    i++;
                }
            }
        }

        ret = JS_PDF_getTimestamp(
            strSrcPath.toLocal8Bit().toStdString().c_str(),
            strPasswd.length() > 0 ? strPasswd.toStdString().c_str() : NULL,
            &binTSP );

        if( binTSP.nLen > 0 )
        {
            mInfoTable->insertRow(i);
            mInfoTable->setRowHeight(i,10);
            mInfoTable->setItem( i, 0, new QTableWidgetItem( tr("TimeStamp" )));
            mInfoTable->setItem( i, 1, new QTableWidgetItem( getHexString( &binTSP ) ));
            i++;
        }

        if( pCertList ) JS_BIN_resetList( &pCertList );
        if( pCRLList ) JS_BIN_resetList( &pCRLList );
        if( pOCSPList ) JS_BIN_resetList( &pOCSPList );
        JS_BIN_reset( &binTSP );
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

    berApplet->messageBox( tr("PDF information import complete"), this );

    JS_PDF_resetSignLabel( &sSignLabel );
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
        strDstPath = QString( "%1/%2_signed.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    JS_PDF_getUTCTime( now_t, sUTCTime, sizeof(sUTCTime));

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
    ret = JS_PDF_verifyCMS( &binData, &binCert, &binCMS, NULL, NULL, 0 );
    berApplet->log( QString( "CMS Verify: %1").arg( ret ));
#endif

    berApplet->log( QString( "CMS[Len:%1]: %2").arg( binCMS.nLen).arg( getHexString( &binCMS )));

    ret = JS_PDF_applyContentsCMS( &binUnsigned, &binCMS );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to apply CMS: %1").arg( JERR(ret)), this );
        goto end;
    }

    JS_BIN_fileWrite( &binUnsigned, strDstPath.toLocal8Bit().toStdString().c_str() );
    berApplet->messageBox( tr("PDF signing was successful"), this );

end :
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

    JByteRange  sRange;
    JPDFInfo    sInfo;

    int nVerifyChain = 0;
    JSignLabel  sSignLabel;

    memset( &sRange, 0x00, sizeof(sRange));
    memset( &sInfo, 0x00, sizeof(sInfo));
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
        nVerifyChain );


    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr( "failed to verify CMS: %1").arg( JERR(ret)), this );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binPDF );
    JS_PDF_resetSignLabel( &sSignLabel );
}

void PDFSignerDlg::clickClearInfo()
{
    mInfoTable->setRowCount(0);
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

void PDFSignerDlg::clickViewCMS()
{
    int ret = 0;
    QString strSrcPath = mSrcPathText->text();
    BIN binCMS = {0,0};

    CMSInfoDlg cmsInfo;

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
    ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(), NULL, &binCMS );
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
    ret = JS_PDF_getContentsFile( strSrcPath.toLocal8Bit().toStdString().c_str(), NULL, &binCMS );
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

void PDFSignerDlg::clickMake()
{
    if( mSignCheck->isChecked() )
        clickMakeSign();
    else
        clickEncrypt();
}

void PDFSignerDlg::clickVerify()
{
    if( mSignCheck->isChecked() )
        clickVerifySign();
    else
        clickDecrypt();
}

#endif
