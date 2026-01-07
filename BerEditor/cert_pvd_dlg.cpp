/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QDir>
#include <QFileInfo>

#include "cert_pvd_dlg.h"
#include "js_pki.h"
#include "js_pki_pvd.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_util.h"
#include "js_error.h"
#include "common.h"

#include "ber_applet.h"
#include "mainwindow.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"
#include "cert_man_dlg.h"

const QString kTypeTCert = "TrustCert";
const QString kTypeUCert = "UntrustCert";
const QString kTypeCRL = "CRL";

const QStringList kParamList = { "Policy", "Purpose", "Name", "Depth", "AuthLevel", "HostName", "Email", "IP" };

CertPVDDlg::CertPVDDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setAcceptDrops( true );

    connect( mPathTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotPathMenu(QPoint)));
    connect( mParamTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotParamMenu(QPoint)));


    connect( mTrustFindBtn, SIGNAL(clicked()), this, SLOT(clickTrustFind()));
    connect( mUntrustFindBtn, SIGNAL(clicked()), this, SLOT(clickUntrustFind()));
    connect( mCRLFindBtn, SIGNAL(clicked()), this, SLOT(clickCRLFind()));

    connect( mPathTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCertCRL()));

    connect( mUseTrustListCheck, SIGNAL(clicked()), this, SLOT(checkUseTrustList()));
    connect( mTrustListBtn, SIGNAL(clicked()), this, SLOT(clickTrustList()));

    connect( mTargetFindBtn, SIGNAL(clicked()), this, SLOT(clickTargetFind()));
    connect( mPolicyCheckBtn, SIGNAL(clicked()), this, SLOT(clickPolicyCheck()));
    connect( mPathValidationBtn, SIGNAL(clicked()), this, SLOT(clickPathValidation()));
    connect( mTrustInfoBtn, SIGNAL(clicked()), this, SLOT(clickTrustInfo()));
    connect( mUntrustInfoBtn, SIGNAL(clicked()), this, SLOT(clickUntrustInfo()));
    connect( mCRLInfoBtn, SIGNAL(clicked()), this, SLOT(clickCRLInfo()));
    connect( mTargetInfoBtn, SIGNAL(clicked()), this, SLOT(clickTargetInfo()));
    connect( mTrustAddBtn, SIGNAL(clicked()), this, SLOT(clickTrustAdd()));
    connect( mUntrustAddBtn, SIGNAL(clicked()), this, SLOT(clickUntrustAdd()));
    connect( mCRLAddBtn, SIGNAL(clicked()), this, SLOT(clickCRLAdd()));

    connect( mListClearBtn, SIGNAL(clicked()), this, SLOT(clickListClear()));
    connect( mPathClearBtn, SIGNAL(clicked()), this, SLOT(clickPathClear()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mVerifyCRLBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCRL()));
    connect( mVerifyCertBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCert()));

    connect( mATTimeCheck, SIGNAL(clicked()), this, SLOT(checkATTime()));
    connect( mParamAddBtn, SIGNAL(clicked()), this, SLOT(clickParamAdd()));
    connect( mParamListClearBtn, SIGNAL(clicked()), this, SLOT(clickParamListClear()));

    connect( mTrustDecodeBtn, SIGNAL(clicked()), this, SLOT(clickTrustDecode()));
    connect( mUntrustDecodeBtn, SIGNAL(clicked()), this, SLOT(clickUntrustDecode()));
    connect( mCRLDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCRLDecode()));
    connect( mTargetDecodeBtn, SIGNAL(clicked()), this, SLOT(clickTargetDecode()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mFlagGroup->layout()->setSpacing(5);

    mTrustInfoBtn->setFixedWidth(34);
    mTrustDecodeBtn->setFixedWidth(34);
    mUntrustInfoBtn->setFixedWidth(34);
    mUntrustDecodeBtn->setFixedWidth(34);
    mCRLInfoBtn->setFixedWidth(34);
    mCRLDecodeBtn->setFixedWidth(34);
    mTargetInfoBtn->setFixedWidth(34);
    mTargetDecodeBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mPathValidationBtn->setFocus();
}

CertPVDDlg::~CertPVDDlg()
{

}

void CertPVDDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void CertPVDDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            QString strPath = url.toLocalFile();
            BIN binData = {0,0};
            QString strType;
            int nSelfSign = 0;
            JCertInfo sCertInfo;

            memset( &sCertInfo, 0x00, sizeof(sCertInfo));

            JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

            if( JS_PKI_getCertInfo2( &binData, &sCertInfo, NULL, &nSelfSign) == JSR_OK )
            {
                if( mUseTrustListCheck->isChecked() == true )
                {
                    strType = kTypeUCert;
                }
                else
                {
                    if( nSelfSign == 1 )
                        strType = kTypeTCert;
                    else
                        strType = kTypeUCert;
                }
            }
            else
            {
                if( JS_PKI_isCRL( &binData ) == 1 )
                {
                    strType = kTypeCRL;
                }
                else
                {
                    JS_BIN_reset( &binData );
                    continue;
                }
            }

            mPathTable->insertRow( 0 );
            mPathTable->setRowHeight( 0, 10 );
            mPathTable->setItem( 0, 0, new QTableWidgetItem( strType ));
            mPathTable->setItem( 0, 1, new QTableWidgetItem( strPath ));

            JS_BIN_reset( &binData );
            JS_PKI_resetCertInfo( &sCertInfo );
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void CertPVDDlg::initialize()
{
    QStringList sPathLabels = { tr( "Type"), tr( "Path" ) };

    mPathTable->clear();
    mPathTable->horizontalHeader()->setStretchLastSection(true);
    mPathTable->setColumnCount(2);
    mPathTable->setHorizontalHeaderLabels( sPathLabels );
    mPathTable->verticalHeader()->setVisible(false);
    mPathTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPathTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mPathTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPathTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sParamLabels = { tr( "Param"), tr( "Value" ) };

    mParamTable->clear();
    mParamTable->horizontalHeader()->setStretchLastSection(true);
    mParamTable->setColumnCount(2);
    mParamTable->setHorizontalHeaderLabels( sParamLabels );
    mParamTable->verticalHeader()->setVisible(false);
    mParamTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mParamTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mParamTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mParamTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QDateTime dateTime = QDateTime::currentDateTime();
    mVerifyDateTime->setDateTime(dateTime);

    mParamCombo->addItems( kParamList );
    mParamValueText->setPlaceholderText( tr("String value" ));

    mTrustPathText->setPlaceholderText( tr( "Trust anchor certificate file path") );
    mUntrustPathText->setPlaceholderText( tr( "Intermediate CA certificate file path" ));
    mCRLPathText->setPlaceholderText( tr("CRL file path" ));

    checkATTime();
    checkUseTrustList();

    mTargetPathText->setFocus();
    mTargetPathText->setPlaceholderText( tr( "Select CertMan certificate" ) );
}

void CertPVDDlg::slotPathMenu( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction* delAct = new QAction( tr("Delete" ), this );
    QAction* sendAct = new QAction( tr( "Send target" ), this );

    QModelIndex idx = mPathTable->currentIndex();
    QTableWidgetItem *pItem = mPathTable->item( idx.row(), 0 );
    if( pItem == nullptr ) return;

    QString strType = pItem->text();

    connect( delAct, SIGNAL(triggered(bool)), this, SLOT(delPath()));
    connect( sendAct, SIGNAL(triggered(bool)), this, SLOT( sendTarget()));

    if( strType == kTypeUCert )
        menu->addAction( sendAct );

    menu->addAction( delAct );

    menu->popup( mPathTable->viewport()->mapToGlobal(pos));
}

void CertPVDDlg::slotParamMenu( QPoint pos )
{
    QMenu *menu = new QMenu(this);
    QAction* delAct = new QAction( tr("Delete" ), this );

    QModelIndex idx = mParamTable->currentIndex();
    QTableWidgetItem *pItem = mParamTable->item( idx.row(), 0 );
    if( pItem == nullptr ) return;

    connect( delAct, SIGNAL(triggered(bool)), this, SLOT(delParam()));

    menu->addAction( delAct );
    menu->popup( mParamTable->viewport()->mapToGlobal(pos));
}

void CertPVDDlg::delPath()
{
    QModelIndex idx = mPathTable->currentIndex();
    QTableWidgetItem* item = mPathTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    mPathTable->removeRow( idx.row() );
}

void CertPVDDlg::sendTarget()
{
    QModelIndex idx = mPathTable->currentIndex();
    QTableWidgetItem* item = mPathTable->item( idx.row(), 0 );
    QTableWidgetItem* item1 = mPathTable->item( idx.row(), 1 );
    if( item == NULL || item1 == NULL ) return;

    mTargetPathText->setText( item1->text() );
    mPathTable->removeRow( idx.row() );
}

void CertPVDDlg::delParam()
{
    QModelIndex idx = mParamTable->currentIndex();
    QTableWidgetItem* item = mParamTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    mParamTable->removeRow( idx.row() );
}


void CertPVDDlg::clickViewCertCRL()
{
    QString strPath;

    QModelIndex idx = mPathTable->currentIndex();
    QTableWidgetItem* item = mPathTable->item( idx.row(), 0 );
    if( item == NULL ) return;

    QTableWidgetItem* item1 = mPathTable->item( idx.row(), 1 );
    if( item1 == NULL ) return;

    strPath = item1->text();

    if( item->text() == kTypeCRL )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRLPath( item1->text() );
        crlInfo.exec();
    }
    else
    {
        CertInfoDlg certInfo;
        certInfo.setCertPath( item1->text() );
        certInfo.exec();
    }
}

void CertPVDDlg::clickTrustFind()
{
    QString strPath = mTrustPathText->text();

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
    {
        mTrustPathText->setText( strFile );
    }
}

void CertPVDDlg::clickUntrustFind()
{
    QString strPath = mUntrustPathText->text();

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
    {
        mUntrustPathText->setText( strFile );
    }
}

void CertPVDDlg::clickCRLFind()
{
    QString strPath = mCRLPathText->text();

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_CRL, strPath );
    if( strFile.length() > 0 )
    {
        mCRLPathText->setText( strFile );
    }
}

void CertPVDDlg::clickTargetFind()
{
    QString strPath = mTargetPathText->text();

    QString strFile = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
    {
        mTargetPathText->setText( strFile );
    }
}

void CertPVDDlg::checkUseTrustList()
{
    bool bVal = mUseTrustListCheck->isChecked();

    mTrustBtn->setEnabled( !bVal );
    mTrustLabel->setEnabled( !bVal );
    mTrustPathText->setEnabled( !bVal );
    mTrustFindBtn->setEnabled( !bVal );
    mTrustAddBtn->setEnabled( !bVal );
    mTrustInfoBtn->setEnabled( !bVal );
    mTrustDecodeBtn->setEnabled( !bVal );

    mTrustListBtn->setEnabled( bVal );
}

void CertPVDDlg::clickTrustList()
{
//    TrustListDlg trustList;
//    trustList.exec();
    CertManDlg certMan;
    certMan.setMode( ManModeTrust );
    certMan.setTitle( tr( "Trust RootCA List" ));
    certMan.exec();
}

void CertPVDDlg::clickVerifyCert()
{
    int ret = 0;
    char sMsg[1024];

    BIN binTrust = {0,0};
    BIN binUntrust = {0,0};
    BIN binCRL = {0,0};

    QString strTrustPath = mTrustPathText->text();
    QString strUntrustPath = mUntrustPathText->text();
    QString strCLRPath = mCRLPathText->text();

    if( mUseTrustListCheck->isChecked() == false )
    {
        if( strTrustPath.length() > 1 )
        {
            JS_BIN_fileReadBER( strTrustPath.toLocal8Bit().toStdString().c_str(), &binTrust );
        }
        else
        {
            berApplet->warningBox( "Select trust certificate", this );
            mTrustPathText->setFocus();
            goto end;
        }
    }

    if( strUntrustPath.length() > 1 )
    {
        JS_BIN_fileReadBER( strUntrustPath.toLocal8Bit().toStdString().c_str(), &binUntrust );
    }
    else
    {
        berApplet->warningBox( "Select untrust certificate", this );
        mUntrustPathText->setFocus();
        goto end;
    }

    if( strCLRPath.length() > 1 )
    {
        JS_BIN_fileReadBER( strCLRPath.toLocal8Bit().toStdString().c_str(), &binCRL );
    }

    if( mUseTrustListCheck->isChecked() == true )
    {
        QString strTrustPath = berApplet->settingsMgr()->trustCertPath();
        ret = JS_PKI_CertVerifyByCAPath( strTrustPath.toLocal8Bit().toStdString().c_str(), &binCRL, &binUntrust, sMsg );
    }
    else
    {
        ret = JS_PKI_CertVerifyByCA( &binTrust, &binCRL, &binUntrust, sMsg );
    }
    berApplet->log( QString( "Certificate verification result by CA : %1").arg(ret));

    if( ret == 1 )
    {
        QString strOK = tr( "The certificate verification (byCA) successful" );
        berApplet->messageLog( strOK, this );
    }
    else
    {
        QString strErr = tr( "The certificate verification (byCA) failed: %1" ).arg(sMsg);
        berApplet->warnLog( strErr, this );
    }

    ret = JS_PKI_verifyCert( &binTrust, &binCRL, &binUntrust, sMsg );
    berApplet->log( QString( "Certificate verification result : %1").arg(ret));
    if( ret != 1 ) berApplet->elog( QString("Certificate verification failed: %1").arg(sMsg));

end :
    JS_BIN_reset( &binTrust );
    JS_BIN_reset( &binUntrust );
    JS_BIN_reset( &binCRL );
}

void CertPVDDlg::clickVerifyCRL()
{
    int ret = 0;
    bool bTrust = true;
    QString strMsg;

    BIN binCRL = {0,0};
    BIN binCA = {0,0};

    QString strCAPath = mTrustPathText->text();
    QString strCRLPath = mCRLPathText->text();

    if( strCAPath.length() < 1 )
    {
        strCAPath = mUntrustPathText->text();
        bTrust = false;
    }

    if( strCAPath.length() < 1 )
    {
        berApplet->warningBox( "Select trust certificate or untrust certificate", this );
        goto end;
    }

    if( strCRLPath.length() < 1 )
    {
        berApplet->warningBox( "Select CRL", this );
        mCRLPathText->setFocus();
        goto end;
    }

    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );
    JS_BIN_fileReadBER( strCRLPath.toLocal8Bit().toStdString().c_str(), &binCRL );

    ret = JS_PKI_verifyCRL( &binCRL, &binCA );

    if( ret == 1 )
    {
        strMsg = QString( "CRL verification successful with %1").arg( bTrust ? "Trust Cert" : "Untrust Cert");
        berApplet->messageBox( strMsg, this );
        berApplet->log( strMsg );
    }
    else
    {
        strMsg = QString( "CRL verification failed with %1").arg( bTrust ? "Trust Cert" : "Untrust Cert" );
        berApplet->warningBox( strMsg, this );
        berApplet->elog( strMsg );
    }


end :
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCRL );
}

static void _addParamFlag( JNumValList **ppParamList, int nFlag )
{
    JNumVal sNumVal;
    char sFlag[16];
    sprintf( sFlag, "%d", nFlag );

    JS_UTIL_setNumVal( &sNumVal, JS_PVD_VERIFY_FLAG, sFlag );
    JS_UTIL_addNumValList( ppParamList, &sNumVal );
    JS_UTIL_resetNumVal( &sNumVal );
}

static void _addParamValue( JNumValList **ppParamList, int nNum, const char *pValue )
{
    JNumVal sNumVal;
    JS_UTIL_setNumVal( &sNumVal, nNum, pValue );
    JS_UTIL_addNumValList( ppParamList, &sNumVal );
    JS_UTIL_resetNumVal( &sNumVal );
}

static int _getParamID( const QString strParam )
{
    if( strParam.toUpper() == "POLICY" ) return JS_PVD_VERIFY_POLICY;
    else if( strParam.toUpper() == "PURPOSE" ) return JS_PVD_VERIFY_PURPOSE;
    else if( strParam.toUpper() == "NAME" ) return JS_PVD_VERIFY_NAME;
    else if( strParam.toUpper() == "DEPTH" ) return JS_PVD_VERIFY_DEPTH;
    else if( strParam.toUpper() == "AUTHLEVEL" ) return JS_PVD_VERIFY_AUTH_LEVEL;
    else if( strParam.toUpper() == "HOSTNAME" ) return JS_PVD_VERIFY_HOSTNAME;
    else if( strParam.toUpper() == "EMAIL" ) return JS_PVD_VERIFY_EMAIL;
    else if( strParam.toUpper() == "IP" ) return JS_PVD_VERIFY_IP;
    else if( strParam.toUpper() == "FLAG" ) return JS_PVD_VERIFY_FLAG;

    return -1;
}

void CertPVDDlg::clickPolicyCheck()
{
    int ret = 0;

    BIN binCert = {0,0};
    BINList *pCertList = NULL;

//    time_t tCheckTime = 0;

    QString strTrustPath = mTrustPathText->text();
    QString strUntrustPath = mUntrustPathText->text();
    QString strTargetPath = mTargetPathText->text();

    JNumValList *pParamList = NULL;

    int nCount = 0;
    int nExpPolicy = 0;

    if( mUseTrustListCheck->isChecked() == false )
    {
        if( strTrustPath.length() > 1 )
        {
            JS_BIN_fileReadBER( strTrustPath.toLocal8Bit().toStdString().c_str(), &binCert );
            JS_BIN_addList( &pCertList, &binCert );
            JS_BIN_reset( &binCert );
        }
    }

    if( strUntrustPath.length() > 1 )
    {
        JS_BIN_fileReadBER( strUntrustPath.toLocal8Bit().toStdString().c_str(), &binCert );
        JS_BIN_addList( &pCertList, &binCert );
        JS_BIN_reset( &binCert );
    }

    if( strTargetPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strTargetPath = certMan.getSeletedCertPath();
        if( strTargetPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Select target certificate" ), this );
            goto end;
        }
        else
        {
            mTargetPathText->setText( strTargetPath );
        }
    }

    JS_BIN_fileReadBER( strTargetPath.toLocal8Bit().toStdString().c_str(), &binCert );

    nCount = mPathTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        BIN binData = {0,0};
        QString strType = mPathTable->item( i, 0 )->text();
        QString strPath = mPathTable->item( i, 1 )->text();

        JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

        if( strType == kTypeTCert || strType == kTypeUCert )
        {
            JS_BIN_addList( &pCertList, &binData );
        }

        JS_BIN_reset( &binData );
    }

    if( mATTimeCheck->isChecked() )
    {
        QString strValue = QString( "%1" ).arg( mVerifyDateTime->dateTime().toSecsSinceEpoch() );
        berApplet->log( QString( "CheckTime: %1").arg( strValue ));
        _addParamValue( &pParamList, JS_PVD_VERIFY_ATTIME, strValue.toStdString().c_str() );
    }

    if( mUseCheckTimeCheck->isChecked() && mATTimeCheck->isChecked() == false )
    {
//        _addParamFlag( &pParamList, JS_PVD_FLAG_USE_CHECK_TIME );
        QString strValue = QString( "%1" ).arg( time(NULL) );
        berApplet->log( QString( "CheckTime: %1").arg( strValue ));
        _addParamValue( &pParamList, JS_PVD_VERIFY_ATTIME, strValue.toStdString().c_str() );
    }

    if( mCRLCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CRL_CHECK );
    if( mIgnoreCriticalCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_IGNORE_CRITICAL );
    if( mX509StrictCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_X509_STRICT );

    if( mPolicyCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_POLICY_CHECK );
    if( mExplicitPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXPLICIT_POLICY );
    if( mInhibitAnyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_ANY );
    if( mInhibitMapCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_MAP );
    if( mTrustedFirstCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_TRUSTED_FIRST );

    /*
    if( mAllowProxyCertsCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_ALLOW_PROXY_CERTS );
    if( mNotifyPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NOTIFY_POLICY );
    if( mExtendedCRLSupportCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXTENDED_CRL_SUPPORT );
    if( mUseDeltasCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_USE_DELTAS );
    if( mCheckSSSignatureCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CHECK_SS_SIGNATURE );
    if( mNoALTChainsCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NO_ALT_CHAINS );
    if( mSuiteB128LOSOnlyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS_ONLY );
    if( mSuiteB192LOSCheck->isChecked() ) _addParamFlag( &pParamList,JS_PVD_FLAG_SUITEB_192_LOS );
    if( mSuiteB128LOSCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS );
    */

    if( mPartialChainCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_PARTIAL_CHAIN );
    if( mNoCheckTimeCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NO_CHECK_TIME );

    nCount = mParamTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        int nID = 0;
        QString strParam = mParamTable->item( i, 0 )->text();
        QString strValue = mParamTable->item( i, 1 )->text();

        nID = _getParamID( strParam );
        if( nID < 0 ) continue;

        _addParamValue( &pParamList, nID, strValue.toStdString().c_str() );
    }

//    tCheckTime = mVerifyDateTime->dateTime().toSecsSinceEpoch();
    ret = JS_PKI_CheckPolicy( pCertList, pParamList, &nExpPolicy );

    berApplet->log( QString( "Check policy results: Ret %1 ExpPolicy: %2").arg(ret).arg( nExpPolicy));
    if( ret == JSR_VALID )
    {
        QString strOK = tr( "Policy check successful [Explicit Policy: %1]" ).arg( nExpPolicy );
        berApplet->messageLog( strOK, this );
    }
    else
    {
        QString strErr;

        if( ret == -2 )
            strErr = tr( "Validation Fail because X509_V_FLAG_EXPLICIT_POLICY was requested But policy_oids is empty" );
        else if( ret == -1 )
            strErr = tr( "At least one of the certs contains invalid or inconsistent extensions" );
        else if( ret == 0 )
            strErr = tr( "Internal Error" );

        berApplet->warnLog( QString( "%1 [Explicit Policy:%2 Ret:%3]" ).arg( strErr ).arg( nExpPolicy ).arg( ret ), this );
    }

end :
    if( pCertList ) JS_BIN_resetList( &pCertList );
    if( pParamList ) JS_UTIL_resetNumValList( &pParamList );
    JS_BIN_reset( &binCert );
}

void CertPVDDlg::clickPathValidation()
{
    int ret = 0;

    BIN binTrust = {0,0};
    BIN binUntrust = {0,0};
    BIN binCRL = {0,0};
    BIN binTarget = {0,0};

    BINList *pTrustList = NULL;
    BINList *pUntrustList = NULL;
    BINList *pCRLList = NULL;
//    time_t tCheckTime = 0;

    QString strTrustPath = mTrustPathText->text();
    QString strUntrustPath = mUntrustPathText->text();
    QString strCLRPath = mCRLPathText->text();


    JNumValList *pParamList = NULL;

    char sMsg[1024];
    int nCount = 0;
    int nSelfVerify = 0;

    if( mUseTrustListCheck->isChecked() == false )
    {
        if( strTrustPath.length() > 1 )
        {
            JS_BIN_fileReadBER( strTrustPath.toLocal8Bit().toStdString().c_str(), &binTrust );
            JS_BIN_addList( &pTrustList, &binTrust );
            JS_BIN_reset( &binTrust );
        }
    }

    if( strUntrustPath.length() > 1 )
    {
        JS_BIN_fileReadBER( strUntrustPath.toLocal8Bit().toStdString().c_str(), &binUntrust );
        JS_BIN_addList( &pUntrustList, &binUntrust );
        JS_BIN_reset( &binUntrust );
    }

    if( mIncludeCertManCACheck->isChecked() == true )
    {
        QString strPath = berApplet->settingsMgr()->CACertPath();
        QDir dir( strPath );

        for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
        {
            BIN binCA = {0,0};
            QString strName = file.baseName();
            QString strSuffix = file.suffix();

            if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

            JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCA );
            if( binCA.nLen < 1 ) continue;

            if( JS_PKI_isCert( &binCA ) != 1 )
            {
                JS_BIN_reset( &binCA );
                continue;
            }

            JS_BIN_addList( &pUntrustList, &binCA );
            JS_BIN_reset( &binCA );
        }
    }

    if( strCLRPath.length() > 1 )
    {
        JS_BIN_fileReadBER( strCLRPath.toLocal8Bit().toStdString().c_str(), &binCRL );
        JS_BIN_addList( &pCRLList, &binCRL );
        JS_BIN_reset( &binCRL );
    }

    if( mIncludeCertManCRLCheck->isChecked() == true )
    {
        QString strPath = berApplet->settingsMgr()->CRLPath();
        QDir dir( strPath );

        for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
        {
            BIN binCRL = {0,0};
            QString strName = file.baseName();
            QString strSuffix = file.suffix();

            if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

            JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCRL );
            if( binCRL.nLen < 1 ) continue;

            if( JS_PKI_isCRL( &binCRL ) != 1 )
            {
                JS_BIN_reset( &binCRL );
                continue;
            }

            JS_BIN_addList( &pCRLList, &binCRL );
            JS_BIN_reset( &binCRL );
        }
    }

    QString strTargetPath = mTargetPathText->text();
    if( strTargetPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCert);
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        strTargetPath = certMan.getSeletedCertPath();
        if( strTargetPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Select target certificate" ), this );
            goto end;
        }
        else
        {
            mTargetPathText->setText( strTargetPath );
        }
    }

    JS_BIN_fileReadBER( strTargetPath.toLocal8Bit().toStdString().c_str(), &binTarget );

    if( JS_PKI_isSelfSignedCert2( &binTarget, &nSelfVerify ) == JSR_YES )
    {
        berApplet->log( "The target ceritificate is self-signed" );

        if( nSelfVerify == JSR_VALID )
            berApplet->log( "The self signature is good" );
        else
            berApplet->elog( "The self signature is bad" );
    }

    nCount = mPathTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        BIN binData = {0,0};
        QString strType = mPathTable->item( i, 0 )->text();
        QString strPath = mPathTable->item( i, 1 )->text();

        JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

        if( strType == kTypeTCert )
        {
            if( mUseTrustListCheck->isChecked() == false )
            {
                JS_BIN_addList( &pTrustList, &binData );
            }
            else
            {
                berApplet->warnLog( tr( "Trust values ​​are not supported when using a trust list: %1").arg( strPath ), this );
            }
        }
        else if( strType == kTypeUCert )
        {
            JS_BIN_addList( &pUntrustList, &binData );
        }
        else if( strType == kTypeCRL )
        {
            JS_BIN_addList( &pCRLList, &binData );
        }

        JS_BIN_reset( &binData );
    }

    if( mATTimeCheck->isChecked() )
    {
        QString strValue = QString( "%1" ).arg( mVerifyDateTime->dateTime().toSecsSinceEpoch() );
        berApplet->log( QString( "CheckTime: %1").arg( strValue ));
        _addParamValue( &pParamList, JS_PVD_VERIFY_ATTIME, strValue.toStdString().c_str() );
    }

    if( mUseCheckTimeCheck->isChecked() && mATTimeCheck->isChecked() == false )
    {
//        _addParamFlag( &pParamList, JS_PVD_FLAG_USE_CHECK_TIME );
        QString strValue = QString( "%1" ).arg( time(NULL) );
        berApplet->log( QString( "CheckTime: %1").arg( strValue ));
        _addParamValue( &pParamList, JS_PVD_VERIFY_ATTIME, strValue.toStdString().c_str() );
    }

    if( mCRLCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CRL_CHECK );
    if( mIgnoreCriticalCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_IGNORE_CRITICAL );
    if( mX509StrictCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_X509_STRICT );

    if( mPolicyCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_POLICY_CHECK );
    if( mExplicitPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXPLICIT_POLICY );
    if( mInhibitAnyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_ANY );
    if( mInhibitMapCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_MAP );

    if( mTrustedFirstCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_TRUSTED_FIRST );
    /*
    if( mAllowProxyCertsCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_ALLOW_PROXY_CERTS );
    if( mNotifyPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NOTIFY_POLICY );
    if( mExtendedCRLSupportCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXTENDED_CRL_SUPPORT );
    if( mUseDeltasCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_USE_DELTAS );
    if( mCheckSSSignatureCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CHECK_SS_SIGNATURE );
    if( mNoALTChainsCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NO_ALT_CHAINS );
    if( mSuiteB128LOSOnlyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS_ONLY );
    if( mSuiteB192LOSCheck->isChecked() ) _addParamFlag( &pParamList,JS_PVD_FLAG_SUITEB_192_LOS );
    if( mSuiteB128LOSCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS );
    */

    if( mPartialChainCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_PARTIAL_CHAIN );
    if( mNoCheckTimeCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NO_CHECK_TIME );

    nCount = mParamTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        int nID = 0;
        QString strParam = mParamTable->item( i, 0 )->text();
        QString strValue = mParamTable->item( i, 1 )->text();

        nID = _getParamID( strParam );
        if( nID < 0 ) continue;

        _addParamValue( &pParamList, nID, strValue.toStdString().c_str() );
    }

//    tCheckTime = mVerifyDateTime->dateTime().toSecsSinceEpoch();

    if( mUseTrustListCheck->isChecked() )
    {
        QString strTrustPath = berApplet->settingsMgr()->trustCertPath();
        ret = JS_PKI_CertPVD2( strTrustPath.toLocal8Bit().toStdString().c_str(), pUntrustList, pCRLList, pParamList, &binTarget, sMsg );
    }
    else
    {
        ret = JS_PKI_CertPVD( pTrustList, pUntrustList, pCRLList, pParamList, &binTarget, sMsg );
    }

    berApplet->log( QString( "Path verification result : %1").arg(ret));
    if( ret == JSR_VALID )
    {
        QString strOK = tr("The certificate path verification is successful.");
        berApplet->messageLog( strOK, this );
    }
    else
    {
        QString strErr = tr( "The certificate path verification failed [%1]" ).arg(sMsg);
        berApplet->warnLog( strErr, this );
    }

end :
    JS_BIN_reset( &binTrust );
    JS_BIN_reset( &binUntrust );
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binTarget );

    if( pTrustList ) JS_BIN_resetList( &pTrustList );
    if( pUntrustList ) JS_BIN_resetList( &pUntrustList );
    if( pCRLList ) JS_BIN_resetList( &pCRLList );
    if( pParamList ) JS_UTIL_resetNumValList( &pParamList );
}

void CertPVDDlg::clickTrustInfo()
{
    QString strPath = mTrustPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select trust certificate", this );
        mTrustPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void CertPVDDlg::clickUntrustInfo()
{
    QString strPath = mUntrustPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select untrust certificate", this );
        mUntrustPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void CertPVDDlg::clickCRLInfo()
{
    QString strPath = mCRLPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select CRL", this );
        mCRLPathText->setFocus();
        return;
    }

    CRLInfoDlg crlInfoDlg;
    crlInfoDlg.setCRLPath( strPath );
    crlInfoDlg.exec();
}

void CertPVDDlg::clickTargetInfo()
{
    QString strPath = mTargetPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select target ceritifcate", this );
        mTargetPathText->setFocus();
        return;
    }

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertPath( strPath );
    certInfoDlg.exec();
}

void CertPVDDlg::clickTrustAdd()
{
    QString strPath = mTrustPathText->text();

    if( strPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCA);
        certMan.setTitle( tr( "Select trust CA certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return;

        strPath = certMan.getSeletedCAPath();
        if( strPath.length() < 1 )
        {
            berApplet->warningBox( "Select trust CA certificate", this );
            return;
        }
        else
        {
            mTrustPathText->setText( strPath );
        }
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( 0 );
    mPathTable->setRowHeight( 0, 10 );
    mPathTable->setItem( 0, 0, new QTableWidgetItem( kTypeTCert ));
    mPathTable->setItem( 0, 1, new QTableWidgetItem( strPath ));

    mTrustPathText->clear();
}

void CertPVDDlg::clickUntrustAdd()
{
    QString strPath = mUntrustPathText->text();

    if( strPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCA);
        certMan.setTitle( tr( "Select untrust CA certificate" ));
        if( certMan.exec() != QDialog::Accepted )
            return;

        strPath = certMan.getSeletedCAPath();
        if( strPath.length() < 1 )
        {
            berApplet->warningBox( "Select untrust CA certificate", this );
            return;
        }
        else
        {
            mUntrustPathText->setText( strPath );
        }
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( 0 );
    mPathTable->setRowHeight( 0, 10 );
    mPathTable->setItem( 0, 0, new QTableWidgetItem( kTypeUCert ));
    mPathTable->setItem( 0, 1, new QTableWidgetItem( strPath ));

    mUntrustPathText->clear();
}

void CertPVDDlg::clickCRLAdd()
{
    QString strPath = mCRLPathText->text();

    if( strPath.length() < 1 )
    {
        CertManDlg certMan;
        certMan.setMode(ManModeSelCRL);
        certMan.setTitle( tr( "Select CRL" ));
        if( certMan.exec() != QDialog::Accepted )
            return;

        strPath = certMan.getSeletedCRLPath();
        if( strPath.length() < 1 )
        {
            berApplet->warningBox( "Select CRL", this );
            return;
        }
        else
        {
            mCRLPathText->setText( strPath );
        }
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( 0 );
    mPathTable->setRowHeight( 0, 10 );
    mPathTable->setItem( 0, 0, new QTableWidgetItem( kTypeCRL ));
    mPathTable->setItem( 0, 1, new QTableWidgetItem( strPath ));

    mCRLPathText->clear();
}

void CertPVDDlg::clickListClear()
{   
    mPathTable->setRowCount( 0 );
}

void CertPVDDlg::clickPathClear()
{
    mTrustPathText->clear();
    mUntrustPathText->clear();
    mCRLPathText->clear();
    mTargetPathText->clear();
}

void CertPVDDlg::checkATTime()
{
    bool bVal = mATTimeCheck->isChecked();
    mVerifyDateTime->setEnabled(bVal);

    mUseCheckTimeCheck->setDisabled( bVal );
}

void CertPVDDlg::clickParamAdd()
{
    QString strName = mParamCombo->currentText();
    QString strValue = mParamValueText->text();

    if( strValue.length() < 1 )
    {
        berApplet->warningBox( "Please enter parameter value", this );
        mParamValueText->setFocus();
        return;
    }

    int row = mParamTable->rowCount();
    mParamTable->insertRow( 0 );
    mParamTable->setRowHeight( 0, 10 );
    mParamTable->setItem( 0, 0, new QTableWidgetItem( strName ));
    mParamTable->setItem( 0, 1, new QTableWidgetItem( strValue ));

    mParamValueText->clear();
}

void CertPVDDlg::clickParamListClear()
{    
    mParamTable->setRowCount(0);
}

void CertPVDDlg::clickTrustDecode()
{
    BIN binData = {0,0};
    QString strPath = mTrustPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select trust certificate", this );
        mTrustPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CertPVDDlg::clickUntrustDecode()
{
    BIN binData = {0,0};
    QString strPath = mUntrustPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select untrust certificate", this );
        mUntrustPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CertPVDDlg::clickCRLDecode()
{
    BIN binData = {0,0};
    QString strPath = mCRLPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select CRL", this );
        mCRLPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CertPVDDlg::clickTargetDecode()
{
    BIN binData = {0,0};
    QString strPath = mTargetPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "Select target ceritifcate", this );
        mTargetPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binData );

    if( binData.nLen < 1 )
    {
        berApplet->warningBox( tr("failed to read data"), this );
        return;
    }

    berApplet->decodeData( &binData, strPath );

    JS_BIN_reset( &binData );
}

void CertPVDDlg::clickClearDataAll()
{
    clickListClear();
    clickPathClear();
    clickParamListClear();

    mTrustPathText->clear();
    mUntrustPathText->clear();
    mCRLPathText->clear();
    mTargetPathText->clear();
    mParamValueText->clear();

    mUseCheckTimeCheck->setChecked(false);
    mCRLCheckCheck->setChecked(false);
    mCRLCheckAllCheck->setChecked(false);
    mIgnoreCriticalCheck->setChecked(false);
    mX509StrictCheck->setChecked(false);

    mPolicyCheckCheck->setChecked(false);
    mExplicitPolicyCheck->setChecked(false);
    mInhibitAnyCheck->setChecked(false);
    mInhibitMapCheck->setChecked(false);
    mTrustedFirstCheck->setChecked(false);

    /*
    mNotifyPolicyCheck->setChecked(false);
    mExtendedCRLSupportCheck->setChecked(false);
    mUseDeltasCheck->setChecked(false);
    mCheckSSSignatureCheck->setChecked(false);
    mNoALTChainsCheck->setChecked(false);
    mAllowProxyCertsCheck->setChecked(false);
    mSuiteB128LOSCheck->setChecked(false);
    mSuiteB192LOSCheck->setChecked(false);
    mSuiteB128LOSOnlyCheck->setChecked(false);
    */

    mPartialChainCheck->setChecked(false);
    mNoCheckTimeCheck->setChecked(false);
}
