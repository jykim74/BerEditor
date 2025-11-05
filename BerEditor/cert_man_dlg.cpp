#include <QDir>
#include <QFileInfo>
#include <QDateTime>
#include <QMenu>

#include "cert_man_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "passwd_dlg.h"
#include "new_passwd_dlg.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "pri_key_info_dlg.h"
#include "export_dlg.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_error.h"
#include "js_util.h"
#include "js_pki_tools.h"

static const QString kCertFile = "js_cert.crt";
static const QString kPriKeyFile = "js_private.key";

static QStringList kVersionList = { "V1", "V2" };
static QStringList kPBEv1List = { "PBE-SHA1-3DES", "PBE-SHA1-2DES" };
static QStringList kPBEv2List = { "AES-128-CBC", "AES-256-CBC", "ARIA-128-CBC", "ARIA-256-CBC" };

static QStringList kKeyTypeList = {
    "ALL", JS_PKI_KEY_NAME_RSA, JS_PKI_KEY_NAME_ECDSA, JS_PKI_KEY_NAME_DSA,
    JS_PKI_KEY_NAME_SM2, JS_PKI_KEY_NAME_EDDSA
};

static QStringList kPQCKeyTypeList = {
    JS_PKI_KEY_NAME_ML_DSA, JS_PKI_KEY_NAME_SLH_DSA
};

CertManDlg::CertManDlg(QWidget *parent) :
    QDialog(parent)
{
    mode_ = ManModeBase;
    is_pqc_ = true;

    load_ee_ = false;
    load_other_ = false;
    load_ca_ = false;
    load_crl_ = false;
    load_trust_ = false;

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &cert_, 0x00, sizeof(BIN));
    memset( &ca_cert_, 0x00, sizeof(BIN));
    memset( &crl_, 0x00, sizeof(BIN));

    setupUi(this);
    initUI();

    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    connect( mEE_CertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));
    connect( mOther_CertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotOtherTableMenuRequested(QPoint)));
    connect( mCA_CertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCATableMenuRequested(QPoint)));
    connect( mCRL_Table, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCRLTableMenuRequested(QPoint)));
    connect( mRCA_CertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTrustTableMenuRequested(QPoint)));

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyTypeChanged(int)));
    connect( mOtherKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(otherKeyTypeChanged(int)));
    connect( mCAKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(CAKeyTypeChanged(int)));
    connect( mRCAKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(RCAKeyTypeChanged(int)));

    connect( mTLVersionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeTLVerison(int)));

    connect( mViewCertBtn, SIGNAL(clicked()), this, SLOT(clickViewCert()));
    connect( mDelCertBtn, SIGNAL(clicked()), this, SLOT(clickDeleteCert()));
    connect( mDecodeCertBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCert()));
    connect( mDecodePriKeyBtn, SIGNAL(clicked()), this, SLOT(clickDecodePriKey()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mImportBtn, SIGNAL(clicked()), this, SLOT(clickImport()));
    connect( mExportBtn, SIGNAL(clicked()), this, SLOT(clickExport()));
    connect( mChangePasswdBtn, SIGNAL(clicked()), this, SLOT(clickChangePasswd()));
    connect( mViewPriKeyBtn, SIGNAL(clicked()), this, SLOT(clickViewPriKey()));
    connect( mViewPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickViewPubKey()));
    connect( mRunSignBtn, SIGNAL(clicked()), this, SLOT(clickRunSign()));
    connect( mRunVerifyBtn, SIGNAL(clicked()), this, SLOT(clickRunVerify()));
    connect( mRunPubEncBtn, SIGNAL(clicked()), this, SLOT(clickRunPubEnc()));
    connect( mRunPubDecBtn, SIGNAL(clicked()), this, SLOT(clickRunPubDec()));

    connect( mAddCABtn, SIGNAL(clicked()), this, SLOT(clickAddCA()));
    connect( mRemoveCABtn, SIGNAL(clicked()), this, SLOT(clickRemoveCA()));
    connect( mViewCABtn, SIGNAL(clicked()), this, SLOT(clickViewCA()));
    connect( mDecodeCABtn, SIGNAL(clicked()), this, SLOT(clickDecodeCA()));
    connect( mViewPubKeyCABtn, SIGNAL(clicked()), this, SLOT(clickViewPubKeyCA()));
    connect( mExportCABtn, SIGNAL(clicked()), this, SLOT(clickExportCA()));

    connect( mAddOtherBtn, SIGNAL(clicked()), this, SLOT(clickAddOther()));
    connect( mRemoveOtherBtn, SIGNAL(clicked()), this, SLOT(clickRemoveOther()));
    connect( mViewOtherBtn, SIGNAL(clicked()), this, SLOT(clickViewOther()));
    connect( mDecodeOtherBtn, SIGNAL(clicked()), this, SLOT(clickDecodeOther()));
    connect( mViewPubKeyOtherBtn, SIGNAL(clicked()), this, SLOT(clickViewPubKeyOther()));
    connect( mRunOtherVerifyBtn, SIGNAL(clicked()), this, SLOT(clickRunVerifyOther()));
    connect( mRunOtherPubEncBtn, SIGNAL(clicked()), this, SLOT(clickRunPubEncOther()));
    connect( mExportOtherBtn, SIGNAL(clicked()), this, SLOT(clickExportOther()));

    connect( mAddCRLBtn, SIGNAL(clicked()), this, SLOT(clickAddCRL()));
    connect( mRemoveCRLBtn, SIGNAL(clicked()), this, SLOT(clickRemoveCRL()));
    connect( mViewCRLBtn, SIGNAL(clicked()), this, SLOT(clickViewCRL()));
    connect( mDecodeCRLBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCRL()));
    connect( mExportCRLBtn, SIGNAL(clicked()), this, SLOT(clickExportCRL()));

    connect( mAddTrustBtn, SIGNAL(clicked()), this, SLOT(clickAddTrust()));
    connect( mRemoveTrustBtn, SIGNAL(clicked()), this, SLOT(clickRemoveTrust()));
    connect( mViewTrustBtn, SIGNAL(clicked()), this, SLOT(clickViewTrust()));
    connect( mDecodeTrustBtn, SIGNAL(clicked()), this, SLOT(clickDecodeTrust()));
    connect( mViewPubKeyTrustBtn, SIGNAL(clicked()), this, SLOT(clickViewPubKeyTrust()));
    connect( mExportTrustBtn, SIGNAL(clicked()), this, SLOT(clickExportTrust()));

    connect( mFindTLPriKeyBtn, SIGNAL(clicked()), this, SLOT(findTLPriKey()));
    connect( mFindTLCertBtn, SIGNAL(clicked()), this, SLOT(findTLCert()));
    connect( mFindTLPFXBtn, SIGNAL(clicked()), this, SLOT(findTLPFX()));

    connect( mTLEncPriKeyCheck, SIGNAL(clicked()), this, SLOT(checkTLEncPriKey()));
    connect( mTLPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeTLPriKey()));
    connect( mTLCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeTLCert()));
    connect( mTLPFXDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeTLPFX()));

    connect( mTLPriKeyClearBtn, SIGNAL(clicked()), this, SLOT(clearTLPriKey()));
    connect( mTLCertClearBtn, SIGNAL(clicked()), this, SLOT(clearTLCert()));
    connect( mTLPFXClearBtn, SIGNAL(clicked()), this, SLOT(clearTLPFX()));

    connect( mTLCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickTLCheckKeyPair()));
    connect( mTLViewCertBtn, SIGNAL(clicked()), this, SLOT(clickTLViewCert()));
    connect( mTLEncryptPFXBtn, SIGNAL(clicked()), this, SLOT(clickTLEncryptPFX()));
    connect( mTLDecryptPFXBtn, SIGNAL(clicked()), this, SLOT(clickTLDecryptPFX()));
    connect( mTLSavePFXBtn, SIGNAL(clicked()), this, SLOT(clickTLSavePFX()));
    connect( mTLViewPriKeyBtn, SIGNAL(clicked()), this, SLOT(clickTLViewPriKey()));
    connect( mTLViewPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickTLViewPubKey()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mEETab->layout()->setSpacing(5);
    mEETab->layout()->setMargin(5);

    mOtherTab->layout()->setSpacing(5);
    mOtherTab->layout()->setMargin(5);

    mCATab->layout()->setSpacing(5);
    mCATab->layout()->setMargin(5);

    mCRLTab->layout()->setSpacing(5);
    mCRLTab->layout()->setMargin(5);

    mRCATab->layout()->setSpacing(5);
    mRCATab->layout()->setMargin(5);

    mToolsTab->layout()->setSpacing(5);
    mToolsTab->layout()->setMargin(5);

    mTLPriKeyClearBtn->setFixedWidth(34);
    mTLCertClearBtn->setFixedWidth(34);
    mTLPFXClearBtn->setFixedWidth(34);
    mTLPriKeyDecodeBtn->setFixedWidth(34);
    mTLCertDecodeBtn->setFixedWidth(34);
    mTLPFXDecodeBtn->setFixedWidth(34);
    mTLViewCertBtn->setFixedWidth(34);
    mTLViewPriKeyBtn->setFixedWidth(34);

    mEE_ManGroup->layout()->setSpacing(5);
    mOther_ManGroup->layout()->setSpacing(5);
    mCA_ManGroup->layout()->setSpacing(5);
    mCRL_ManGroup->layout()->setSpacing(5);
    mRCA_ManGroup->layout()->setSpacing(5);
    mTL_ManGroup->layout()->setSpacing(5);

    mOther_ManGroup->layout()->setMargin(5);
    mCA_ManGroup->layout()->setMargin(5);
    mCRL_ManGroup->layout()->setMargin(5);
    mRCA_ManGroup->layout()->setMargin(5);
    mTL_ManGroup->layout()->setMargin(5);
#endif
    mCloseBtn->setDefault(true);
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CertManDlg::~CertManDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &cert_ );
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_reset( &crl_ );
}

void CertManDlg::setTab( int index )
{
    mTabWidget->setCurrentIndex( index );
}

void CertManDlg::setMode( int nMode )
{
    mode_ = nMode;

    if( mode_ == ManModeBase || mode_ == ManModeTrust )
    {
        connect( mEE_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCert()));
        connect( mOther_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewOther()));
        connect( mCA_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCA()));
        connect( mCRL_Table, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewCRL()));
        connect( mRCA_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickViewTrust()));

        mOKBtn->hide();
    }
    else
    {
        connect( mEE_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mOther_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mCA_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mCRL_Table, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mRCA_CertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
    }
}

void CertManDlg::setPQCEnable( bool bVal )
{
    is_pqc_ = bVal;

    mKeyTypeCombo->clear();
    mOtherKeyTypeCombo->clear();
    mCAKeyTypeCombo->clear();
    mRCAKeyTypeCombo->clear();

    mKeyTypeCombo->addItems( kKeyTypeList );
    mOtherKeyTypeCombo->addItems( kKeyTypeList );
    mCAKeyTypeCombo->addItems( kKeyTypeList );
    mRCAKeyTypeCombo->addItems( kKeyTypeList );

    if( bVal == true )
    {
        mKeyTypeCombo->addItems( kPQCKeyTypeList );
        mOtherKeyTypeCombo->addItems( kPQCKeyTypeList );
        mCAKeyTypeCombo->addItems( kPQCKeyTypeList );
        mRCAKeyTypeCombo->addItems( kPQCKeyTypeList );
    }
}

void CertManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void CertManDlg::setKeyAlg( const QString strKeyAlg )
{
    mKeyTypeCombo->setCurrentText( strKeyAlg );
    mOtherKeyTypeCombo->setCurrentText( strKeyAlg );
    mCAKeyTypeCombo->setCurrentText( strKeyAlg );
    mRCAKeyTypeCombo->setCurrentText( strKeyAlg );
}

void CertManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CertManDlg::closeEvent(QCloseEvent *event )
{
    setGroupHide( false );
}

void CertManDlg::changeTab( int index )
{
    if( index == TAB_EE_IDX )
    {
        if( load_ee_ == false )
            loadEEList();
    }
    else if( index == TAB_OTHER_IDX )
    {
        if( load_other_ == false )
            loadOtherList();
    }
    else if( index == TAB_CA_IDX )
    {
        if( load_ca_ == false )
            loadCAList();
    }
    else if( index == TAB_CRL_IDX )
    {
        if( load_crl_ == false )
            loadCRLList();
    }
    else if( index == TAB_TRUST_IDX )
    {
        if( load_trust_ == false )
            loadTrustList();
    }
}

void CertManDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewCertAct = new QAction( tr( "View Cert" ), this );
    QAction *deleteCertAct = new QAction( tr( "Delete Cert" ), this );
    QAction *decodeCertAct = new QAction( tr( "Decode Cert" ), this );
    QAction *changePwdAct = new QAction( tr( "Change Passwd" ), this );
    QAction *exportPFXAct = new QAction( tr( "Export PFX" ), this );
    QAction *checkKeyPairAct = new QAction( tr( "Check KeyPair" ), this );
    QAction *decodePriKeyAct = new QAction( tr( "Decode PriKey" ), this );
    QAction *viewPriKeyAct = new QAction( tr( "View PriKey" ), this );
    QAction *viewPubKeyAct = new QAction( tr("View PubKey"), this );

    connect( viewCertAct, SIGNAL(triggered()), this, SLOT(clickViewCert()));
    connect( deleteCertAct, SIGNAL(triggered()), this, SLOT(clickDeleteCert()));
    connect( decodeCertAct, SIGNAL(triggered()), this, SLOT(clickDecodeCert()));
    connect( changePwdAct, SIGNAL(triggered()), this, SLOT(clickChangePasswd()));
    connect( exportPFXAct, SIGNAL(triggered()), this, SLOT(clickExport()));
    connect( checkKeyPairAct, SIGNAL(triggered()), this, SLOT(clickCheckKeyPair()));
    connect( decodePriKeyAct, SIGNAL(triggered()), this, SLOT(clickDecodePriKey()));
    connect( viewPriKeyAct, SIGNAL(triggered()), this, SLOT(clickViewPriKey()));
    connect( viewPubKeyAct, SIGNAL(triggered()), this, SLOT(clickViewPubKey()));

    menu->addAction( viewCertAct );
    menu->addAction( deleteCertAct );
    menu->addAction( decodeCertAct );
    menu->addAction( changePwdAct );
    menu->addAction( exportPFXAct );
    menu->addAction( checkKeyPairAct );
    menu->addAction( decodePriKeyAct );
    menu->addAction( viewPriKeyAct );
    menu->addAction( viewPubKeyAct );

    menu->popup( mEE_CertTable->viewport()->mapToGlobal(pos));
}

void CertManDlg::slotOtherTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *removeCertAct = new QAction( tr( "Remove Cert" ), this );
    QAction *viewCertAct = new QAction( tr( "View Cert" ), this );
    QAction *decodeCertAct = new QAction( tr( "Decode Cert" ), this );
    QAction *viewPubKeyAct = new QAction( tr( "View PubKey" ), this );
    QAction *exportCertAct = new QAction( tr( "Export Cert" ), this );

    connect( removeCertAct, SIGNAL(triggered()), this, SLOT(clickRemoveOther()));
    connect( viewCertAct, SIGNAL(triggered()), this, SLOT(clickViewOther()));
    connect( decodeCertAct, SIGNAL(triggered()), this, SLOT(clickDecodeOther()));
    connect( viewPubKeyAct, SIGNAL(triggered()), this, SLOT(clickViewPubKeyOther()));
    connect( exportCertAct, SIGNAL(triggered()), this, SLOT(clickExportOther()));

    menu->addAction( removeCertAct );
    menu->addAction( viewCertAct );
    menu->addAction( decodeCertAct );
    menu->addAction( viewPubKeyAct );
    menu->addAction( exportCertAct );


    menu->popup( mOther_CertTable->viewport()->mapToGlobal(pos));
}

void CertManDlg::slotCATableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *removeCAAct = new QAction( tr( "Remove CA" ), this );
    QAction *viewCAAct = new QAction( tr( "View CA" ), this );
    QAction *decodeCAAct = new QAction( tr( "Decode CA" ), this );
    QAction *viewPubKeyAct = new QAction( tr( "View PubKey" ), this );
    QAction *exportCAAct = new QAction( tr( "Export CA" ), this );

    connect( removeCAAct, SIGNAL(triggered()), this, SLOT(clickRemoveCA()));
    connect( viewCAAct, SIGNAL(triggered()), this, SLOT(clickViewCA()));
    connect( decodeCAAct, SIGNAL(triggered()), this, SLOT(clickDecodeCA()));
    connect( viewPubKeyAct, SIGNAL(triggered()), this, SLOT(clickViewPubKeyCA()));
    connect( exportCAAct, SIGNAL(triggered()), this, SLOT(clickExportCA()));

    menu->addAction( removeCAAct );
    menu->addAction( viewCAAct );
    menu->addAction( decodeCAAct );
    menu->addAction( viewPubKeyAct );
    menu->addAction( exportCAAct );

    menu->popup( mCA_CertTable->viewport()->mapToGlobal(pos));
}

void CertManDlg::slotCRLTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *removeCRLAct = new QAction( tr( "Remove CRL" ), this );
    QAction *viewCRLAct = new QAction( tr( "View CRL" ), this );
    QAction *decodeCRLAct = new QAction( tr( "Decode CRL" ), this );
    QAction *exportCRLAct = new QAction( tr( "Export CRL" ), this );

    connect( removeCRLAct, SIGNAL(triggered()), this, SLOT(clickRemoveCRL()));
    connect( viewCRLAct, SIGNAL(triggered()), this, SLOT(clickViewCRL()));
    connect( decodeCRLAct, SIGNAL(triggered()), this, SLOT(clickDecodeCRL()));
    connect( exportCRLAct, SIGNAL(triggered()), this, SLOT(clickExportCRL()));

    menu->addAction( removeCRLAct );
    menu->addAction( viewCRLAct );
    menu->addAction( decodeCRLAct );
    menu->addAction( exportCRLAct );

    menu->popup( mCRL_Table->viewport()->mapToGlobal(pos));
}

void CertManDlg::slotTrustTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *removeTrustAct = new QAction( tr( "Remove Trust" ), this );
    QAction *viewTrustAct = new QAction( tr( "View Trust" ), this );
    QAction *decodeTrustAct = new QAction( tr( "Decode Trust" ), this );
    QAction *viewPubKeyAct = new QAction( tr( "View PubKey" ), this );
    QAction *exportTrustAct = new QAction( tr( "Export Trust" ), this );

    connect( removeTrustAct, SIGNAL(triggered()), this, SLOT(clickRemoveTrust()));
    connect( viewTrustAct, SIGNAL(triggered()), this, SLOT(clickViewTrust()));
    connect( decodeTrustAct, SIGNAL(triggered()), this, SLOT(clickDecodeTrust()));
    connect( viewPubKeyAct, SIGNAL(triggered()), this, SLOT(clickViewPubKeyTrust()));
    connect( exportTrustAct, SIGNAL(triggered()), this, SLOT(clickExportTrust()));

    menu->addAction( removeTrustAct );
    menu->addAction( viewTrustAct );
    menu->addAction( decodeTrustAct );
    menu->addAction( viewPubKeyAct );
    menu->addAction( exportTrustAct );

    menu->popup( mRCA_CertTable->viewport()->mapToGlobal(pos));
}

void CertManDlg::keyTypeChanged( int index )
{
    loadEEList();
}

void CertManDlg::otherKeyTypeChanged( int index )
{
    loadOtherList();
}

void CertManDlg::CAKeyTypeChanged( int index )
{
    loadCAList();
}

void CertManDlg::RCAKeyTypeChanged( int index )
{
    loadTrustList();
}

const QString CertManDlg::getModeName( int nMode )
{
    QString strMode;

    if( nMode == ManModeSelCert )
        strMode = tr("Certificate Only");
    else if( nMode == ManModeSelBoth )
        strMode = tr("Ceritifcate and PrivateKey");
    else if( nMode == ManModeSelCA )
        strMode = tr( "CA certificate" );
    else if( nMode == ManModeSelCRL )
        strMode = tr( "CRL" );
    else if( nMode == ManModeTrust )
        strMode = tr( "TrustRootCA" );
    else
        strMode = tr( "Manage" );

    return strMode;
}

void CertManDlg::changeTLVerison( int index )
{
    mTLModeCombo->clear();

    if( index == 0 )
        mTLModeCombo->addItems( kPBEv1List );
    else
        mTLModeCombo->addItems( kPBEv2List );
}

void CertManDlg::initUI()
{
    mTLCheckKeyPairBtn->setToolTip( tr( "Check if the private key and public key in the certificate match" ) );
    mTLEncryptPFXBtn->setToolTip( tr( "Create a PFX of a private key and certificate" ));
    mTLDecryptPFXBtn->setToolTip( tr( "Extract private key and certificate files from PFX file" ));
    mTLViewPubKeyBtn->setToolTip( tr( "View certificate public key" ));
    mTLSavePFXBtn->setToolTip( tr( "Store PFX certificate and private key in End Entity list" ) );

    mTLVersionCombo->addItems( kVersionList );
    mTLVersionCombo->setCurrentIndex(1);
    changeTLVerison( 1 );

#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif
    mKeyTypeCombo->addItems( kKeyTypeList );
    mKeyTypeCombo->addItems( kPQCKeyTypeList );

    mOtherKeyTypeCombo->addItems( kKeyTypeList );
    mOtherKeyTypeCombo->addItems( kPQCKeyTypeList );

    mCAKeyTypeCombo->addItems( kKeyTypeList );
    mCAKeyTypeCombo->addItems( kPQCKeyTypeList );

    mRCAKeyTypeCombo->addItems( kKeyTypeList );
    mRCAKeyTypeCombo->addItems( kPQCKeyTypeList );

    QStringList sTableLabels = { tr( "Subject DN" ), tr( "Expire" ), tr( "Issuer DN" ) };

    mEE_CertTable->clear();
    mEE_CertTable->horizontalHeader()->setStretchLastSection(true);
    mEE_CertTable->setColumnCount( sTableLabels.size() );
    mEE_CertTable->setHorizontalHeaderLabels( sTableLabels );
    mEE_CertTable->verticalHeader()->setVisible(false);
    mEE_CertTable->setStyleSheet( kSelectStyle );
    mEE_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mEE_CertTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mEE_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mEE_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mEE_CertTable->setColumnWidth( 0, nWidth * 8/20 );
    mEE_CertTable->setColumnWidth( 1, nWidth * 5/20 );
 //   mEE_CertTable->setColumnWidth( 2, nWidth * 3/10 );


    QStringList sOtherTableLabels = { tr( "Subject DN" ), tr( "Expire" ), tr( "Issuer DN" ) };

    mOther_CertTable->clear();
    mOther_CertTable->horizontalHeader()->setStretchLastSection(true);
    mOther_CertTable->setColumnCount( sOtherTableLabels.size() );
    mOther_CertTable->setHorizontalHeaderLabels( sOtherTableLabels );
    mOther_CertTable->verticalHeader()->setVisible(false);
    mOther_CertTable->setStyleSheet( kSelectStyle );
    mOther_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mOther_CertTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mOther_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mOther_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);


    mOther_CertTable->setColumnWidth( 0, nWidth * 5/10 );
    mOther_CertTable->setColumnWidth( 1, nWidth * 2/10 );
    mOther_CertTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sCATableLabels = { tr( "Subject DN" ), tr( "Expire" ), tr( "Issuer DN" ) };

    mCA_CertTable->clear();
    mCA_CertTable->horizontalHeader()->setStretchLastSection(true);
    mCA_CertTable->setColumnCount( sCATableLabels.size() );
    mCA_CertTable->setHorizontalHeaderLabels( sCATableLabels );
    mCA_CertTable->verticalHeader()->setVisible(false);
    mCA_CertTable->setStyleSheet( kSelectStyle );
    mCA_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCA_CertTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCA_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCA_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCA_CertTable->setColumnWidth( 0, nWidth * 5/10 );
    mCA_CertTable->setColumnWidth( 1, nWidth * 2/10 );
    mCA_CertTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sCRLTableLabels = { tr( "Issuer DN" ), tr( "This Update"), tr( "Next Update" ) };

    mCRL_Table->clear();
    mCRL_Table->horizontalHeader()->setStretchLastSection(true);
    mCRL_Table->setColumnCount( sCRLTableLabels.size() );
    mCRL_Table->setHorizontalHeaderLabels( sCRLTableLabels );
    mCRL_Table->verticalHeader()->setVisible(false);
    mCRL_Table->setStyleSheet( kSelectStyle );
    mCRL_Table->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRL_Table->setSelectionMode(QAbstractItemView::SingleSelection);
    mCRL_Table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRL_Table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCRL_Table->setColumnWidth( 0, nWidth * 6/10 );
    mCRL_Table->setColumnWidth( 1, nWidth * 2/10 );
    mCRL_Table->setColumnWidth( 2, nWidth * 2/10 );

    QStringList sRCATableLabels = { tr( "Name" ), tr( "Subject DN" ), tr( "Expire" ) };

    mRCA_CertTable->clear();
    mRCA_CertTable->horizontalHeader()->setStretchLastSection(true);
    mRCA_CertTable->setColumnCount( sRCATableLabels.size() );
    mRCA_CertTable->setHorizontalHeaderLabels( sRCATableLabels );
    mRCA_CertTable->verticalHeader()->setVisible(false);
    mRCA_CertTable->setStyleSheet( kSelectStyle );
    mRCA_CertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRCA_CertTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mRCA_CertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRCA_CertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mRCA_CertTable->setColumnWidth( 0, nWidth * 2/10 );
    mRCA_CertTable->setColumnWidth( 1, nWidth * 6/10 );
    mRCA_CertTable->setColumnWidth( 2, nWidth * 2/10 );

    mTLPriKeyPathText->setPlaceholderText( tr("Find a private key") );
    mTLCertPathText->setPlaceholderText( tr("Find a certificate") );
    mTLPFXPathText->setPlaceholderText( tr("Find a PFX") );
}

void CertManDlg::initialize()
{
    mCertPathText->setText( berApplet->settingsMgr()->EECertPath() );
    mOtherCertPathText->setText( berApplet->settingsMgr()->otherCertPath());
    mCAPathText->setText( berApplet->settingsMgr()->CACertPath() );
    mCRLPathText->setText( berApplet->settingsMgr()->CRLPath() );
    mTrustRCAPathText->setText( berApplet->settingsMgr()->trustCertPath() );

    if( mode_ == ManModeSelCert )
    {
        mEE_PasswdLabel->setEnabled(false);
        mEE_PasswdText->setEnabled(false);
    }
    else
    {
        mEE_PasswdLabel->setEnabled(true);
        mEE_PasswdText->setEnabled(true);
    }

    if( mode_ == ManModeTrust )
    {
        setTrustOnly();
        setGroupHide( false );
        mTabWidget->setCurrentIndex(TAB_OTHER_IDX);
        mTabWidget->setTabEnabled( TAB_EE_IDX, false );
        mTabWidget->setTabEnabled( TAB_OTHER_IDX, false );
        mTabWidget->setTabEnabled( TAB_CA_IDX, false );
        mTabWidget->setTabEnabled( TAB_CRL_IDX, false );
        mTabWidget->setTabEnabled( TAB_TRUST_IDX, true );
        mTabWidget->setTabEnabled( TAB_TOOL_IDX, false );

        changeTab(TAB_OTHER_IDX);
    }
    else if( mode_ == ManModeSelBoth || mode_ == ManModeSelCert )
    {
        setGroupHide(true);
        mTabWidget->setTabEnabled( TAB_EE_IDX, true );

        if( mode_ == ManModeSelBoth )
        {
            mTabWidget->setCurrentIndex(TAB_EE_IDX);
            mTabWidget->setTabEnabled( TAB_OTHER_IDX, false );
            changeTab(TAB_EE_IDX);
        }
        else
        {
            mTabWidget->setCurrentIndex(TAB_OTHER_IDX);
            mTabWidget->setTabEnabled( TAB_OTHER_IDX, true );
            changeTab( TAB_OTHER_IDX );
        }

        mTabWidget->setTabEnabled( TAB_CA_IDX, false );
        mTabWidget->setTabEnabled( TAB_CRL_IDX, false );
        mTabWidget->setTabEnabled( TAB_TRUST_IDX, false );
        mTabWidget->setTabEnabled( TAB_TOOL_IDX, false );
    }
    else if( mode_ == ManModeSelCA )
    {
        setGroupHide(true);
        mTabWidget->setCurrentIndex(TAB_CA_IDX);
        mTabWidget->setTabEnabled( TAB_EE_IDX, false );
        mTabWidget->setTabEnabled( TAB_OTHER_IDX, false );
        mTabWidget->setTabEnabled( TAB_CA_IDX, true );
        mTabWidget->setTabEnabled( TAB_CRL_IDX, false );
        mTabWidget->setTabEnabled( TAB_TRUST_IDX, true );
        mTabWidget->setTabEnabled( TAB_TOOL_IDX, false );

        changeTab( TAB_CA_IDX );
    }
    else if( mode_ == ManModeSelCRL )
    {
        setGroupHide(true);
        mTabWidget->setCurrentIndex(TAB_CRL_IDX);
        mTabWidget->setTabEnabled( TAB_EE_IDX, false );
        mTabWidget->setTabEnabled( TAB_OTHER_IDX, false );
        mTabWidget->setTabEnabled( TAB_CA_IDX, false );
        mTabWidget->setTabEnabled( TAB_CRL_IDX, true );
        mTabWidget->setTabEnabled( TAB_TRUST_IDX, false );
        mTabWidget->setTabEnabled( TAB_TOOL_IDX, false );

        changeTab( TAB_CRL_IDX );
    }
    else
    {
        mTabWidget->setCurrentIndex(TAB_EE_IDX);
        changeTab( TAB_EE_IDX );
        setGroupHide( false );
    }

    mModeLabel->setText( getModeName(mode_));
    if( mode_ != ManModeBase ) mOKBtn->setDefault(true);
}

void CertManDlg::setGroupHide( bool bHide )
{
    if( bHide == true )
    {
        mEE_ManGroup->hide();
        mOther_ManGroup->hide();
        mCA_ManGroup->hide();
        mCRL_ManGroup->hide();
        mRCA_ManGroup->hide();
    }
    else
    {
        mEE_ManGroup->show();
        mOther_ManGroup->show();
        mCA_ManGroup->show();
        mCRL_ManGroup->show();
        mRCA_ManGroup->show();
    }
}

void CertManDlg::setOKHide( bool bHide )
{
    if( bHide == true )
        mOKBtn->hide();
    else
        mOKBtn->show();
}

void CertManDlg::setTrustOnly()
{
    setOKHide(true);
    setGroupHide( false );

    mTabWidget->setTabEnabled(0,false);
    mTabWidget->setTabEnabled(1,false);
    mTabWidget->setCurrentIndex(2);
}

const QString CertManDlg::getPriKeyHex()
{
    return getHexString( &pri_key_ );
}

const QString CertManDlg::getCertHex()
{
    return getHexString( &cert_ );
}

const QString CertManDlg::getCACertHex()
{
    return getHexString( &ca_cert_ );
}

const QString CertManDlg::getCRLHex()
{
    return getHexString( &crl_ );
}

int CertManDlg::getPriKey( BIN *pPriKey )
{
    if( pri_key_.nLen < 1 ) return -1;

    JS_BIN_copy( pPriKey, &pri_key_ );
    return 0;
}

int CertManDlg::getCert( BIN *pCert )
{
    if( cert_.nLen < 1 ) return -1;

    JS_BIN_copy( pCert, &cert_ );
    return 0;
}

int CertManDlg::getCACert( BIN *pCA )
{
    if( ca_cert_.nLen < 1 ) return -1;

    JS_BIN_copy( pCA, &ca_cert_ );
    return 0;
}

int CertManDlg::getCRL( BIN *pCRL )
{
    if( crl_.nLen < 1 ) return -1;

    JS_BIN_copy( pCRL, &crl_ );
    return 0;
}

void CertManDlg::clearCAList()
{
    mCA_CertTable->setRowCount(0);
//    load_ca_ = false;
}

void CertManDlg::clearCRLList()
{
    mCRL_Table->setRowCount(0);
//    load_crl_ = false;
}

void CertManDlg::clearTrustList()
{
    mRCA_CertTable->setRowCount(0);
//    load_trust_ = false;
}

void CertManDlg::clearEEList()
{
    mEE_CertTable->setRowCount(0);
//    load_ee_ = false;
}

void CertManDlg::clearOtherList()
{
    mOther_CertTable->setRowCount(0);
//    load_other_ = false;
}

void CertManDlg::loadEEList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearEEList();

    QString strPath = berApplet->settingsMgr()->EECertPath();
    QString strKeyType = mKeyTypeCombo->currentText();

    QDir dir( strPath );

    for (const QFileInfo &folder : dir.entryInfoList(QDir::Dirs))
    {
        if( folder.isFile() ) continue;

        QString strCertPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kCertFile );
        QFileInfo certFile( strCertPath );
        QString strPriKeyPath = QString( "%1/%2" ).arg( folder.filePath() ).arg( kPriKeyFile );
        QFileInfo priKeyFile( strPriKeyPath );

        if( certFile.exists() == false || priKeyFile.exists() == false ) continue;

        //loadList( folder.absoluteFilePath() );

        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;


        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = certFile.baseName();
        QString strSuffix = certFile.suffix();

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        if( nKeyType < 0 ) continue;

        if( strKeyType == JS_PKI_KEY_NAME_RSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ECDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SM2 )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SM2 )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_EDDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ML_DSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SLH_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SLH_DSA )
                continue;
        }
        else
        {
            if( is_pqc_ == false )
            {
                if( nKeyType == JS_PKI_KEY_TYPE_ML_DSA || nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
                    continue;
            }
        }

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mEE_CertTable->insertRow( row );
        mEE_CertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );
        QTableWidgetItem *item1 = new QTableWidgetItem( sNotAfter );
        QTableWidgetItem *item2 = new QTableWidgetItem( sCertInfo.pIssuerName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, folder.filePath() );
        item1->setIcon(QIcon(":/images/keypair.png"));

        mEE_CertTable->setItem( row, 0, item );
        mEE_CertTable->setItem( row, 1, item1 );
        mEE_CertTable->setItem( row, 2, item2 );

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }

    load_ee_ = true;
}

void CertManDlg::loadOtherList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearOtherList();

    QString strPath = berApplet->settingsMgr()->otherCertPath();
    QString strKeyType = mOtherKeyTypeCombo->currentText();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;


        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();


        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        if( nKeyType < 0 ) continue;

        if( strKeyType == JS_PKI_KEY_NAME_RSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ECDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SM2 )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SM2 )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_EDDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ML_DSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SLH_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SLH_DSA )
                continue;
        }
        else
        {
            if( is_pqc_ == false )
            {
                if( nKeyType == JS_PKI_KEY_TYPE_ML_DSA || nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
                    continue;
            }
        }

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mOther_CertTable->insertRow( row );
        mOther_CertTable->setRowHeight( row, 10 );

        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mOther_CertTable->setItem( row, 0, item );
        mOther_CertTable->setItem( row, 1, new QTableWidgetItem( sNotAfter ));
        mOther_CertTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }

    load_other_ = true;
}

void CertManDlg::loadCAList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearCAList();

    QString strPath = berApplet->settingsMgr()->CACertPath();
    QString strKeyType = mCAKeyTypeCombo->currentText();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();


        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        if( nKeyType < 0 ) continue;

        if( strKeyType == JS_PKI_KEY_NAME_RSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ECDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SM2 )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SM2 )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_EDDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ML_DSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SLH_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SLH_DSA )
                continue;
        }
        else
        {
            if( is_pqc_ == false )
            {
                if( nKeyType == JS_PKI_KEY_TYPE_ML_DSA || nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
                    continue;
            }
        }

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mCA_CertTable->insertRow( row );
        mCA_CertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCertInfo.pSubjectName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mCA_CertTable->setItem( row, 0, item );
        mCA_CertTable->setItem( row, 1, new QTableWidgetItem( sNotAfter ));
        mCA_CertTable->setItem( row, 2, new QTableWidgetItem( sCertInfo.pIssuerName ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }

    load_ca_ = true;
}

void CertManDlg::loadCRLList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearCRLList();

    QString strPath = berApplet->settingsMgr()->CRLPath();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCRL = {0,0};
        JCRLInfo sCRLInfo;
        char    sThisUpdate[64];
        char    sNextUpdate[64];

        memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

        QString strName = file.baseName();
        QString strFileName = file.fileName();
        QString strSuffix = file.suffix();


        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() > 3 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCRL );
        if( binCRL.nLen < 1 ) continue;

        ret = JS_PKI_getCRLInfo( &binCRL, &sCRLInfo, NULL, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCRL );
            continue;
        }

        JS_UTIL_getDate( sCRLInfo.tThisUpdate, sThisUpdate );
        JS_UTIL_getDate( sCRLInfo.tNextUpdate, sNextUpdate );

        mCRL_Table->insertRow( row );
        mCRL_Table->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( sCRLInfo.pIssuerName );

        if( now > sCRLInfo.tNextUpdate )
            item->setIcon(QIcon(":/images/crl_expired.png" ));
        else
            item->setIcon(QIcon(":/images/crl.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mCRL_Table->setItem( row, 0, item );
        mCRL_Table->setItem( row, 1, new QTableWidgetItem( sThisUpdate ));
        mCRL_Table->setItem( row, 2, new QTableWidgetItem( sNextUpdate ));

        JS_BIN_reset( &binCRL );
        JS_PKI_resetCRLInfo( &sCRLInfo );

        row++;
    }

    load_crl_ = true;
}

void CertManDlg::loadTrustList()
{
    int ret = 0;
    int row = 0;
    time_t now = time(NULL);

    clearTrustList();

    QString strPath = berApplet->settingsMgr()->trustCertPath();
    QString strKeyType = mRCAKeyTypeCombo->currentText();

    QDir dir( strPath );
    for (const QFileInfo &file : dir.entryInfoList(QDir::Files))
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        char    sNotBefore[64];
        char    sNotAfter[64];
        int nKeyType = 0;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        QString strName = file.baseName();
        QString strSuffix = file.suffix();


        // if you need absolute path of the file

        if( strName.length() != 8 && strSuffix.length() != 1 ) continue;

        JS_BIN_fileReadBER( file.absoluteFilePath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( binCert.nLen < 1 ) continue;

        nKeyType = JS_PKI_getCertKeyType( &binCert );
        if( nKeyType < 0 ) continue;

        if( strKeyType == JS_PKI_KEY_NAME_RSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ECDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ECDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SM2 )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SM2 )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_EDDSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_EDDSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_ML_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_ML_DSA )
                continue;
        }
        else if( strKeyType == JS_PKI_KEY_NAME_SLH_DSA )
        {
            if( nKeyType != JS_PKI_KEY_TYPE_SLH_DSA )
                continue;
        }
        else
        {
            if( is_pqc_ == false )
            {
                if( nKeyType == JS_PKI_KEY_TYPE_ML_DSA || nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
                    continue;
            }
        }

        ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        if( ret != 0 )
        {
            JS_BIN_reset( &binCert );
            continue;
        }

        JS_UTIL_getDate( sCertInfo.tNotBefore, sNotBefore );
        JS_UTIL_getDate( sCertInfo.tNotAfter, sNotAfter );

        mRCA_CertTable->insertRow( row );
        mRCA_CertTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( strName );

        if( now > sCertInfo.tNotAfter )
            item->setIcon(QIcon(":/images/cert_revoked.png" ));
        else
            item->setIcon(QIcon(":/images/cert.png" ));

        item->setData(Qt::UserRole, file.filePath() );

        mRCA_CertTable->setItem( row, 0, item );
        mRCA_CertTable->setItem( row, 1, new QTableWidgetItem( sCertInfo.pSubjectName ));
        mRCA_CertTable->setItem( row, 2, new QTableWidgetItem( sNotAfter ));

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );

        row++;
    }

    load_trust_ = true;
}

int CertManDlg::writePriKeyCert( const BIN *pEncPriKey, const BIN *pCert )
{
    int ret = 0;
    JCertInfo sCertInfo;
    QString strPath = berApplet->settingsMgr()->EECertPath();

    QString strPriPath;
    QString strCertPath;
    QDir dir;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to decode certificate: %1" ).arg( ret ) );
        goto end;
    }

    strPath += "/";

    if( sCertInfo.pSubjectName )
    {
        strPath += sCertInfo.pSubjectName;
    }
    else
    {
        strPath += QDateTime::currentDateTime().toString( "yyyyMMddHHmmss" );
    }

    if( dir.exists( strPath ) == true )
    {
        berApplet->elog( QString( "the path(%1) is already exist").arg( strPath ) );
        ret = JSR_FILE_ALREADY_EXIST;
        goto end;
    }

    if( dir.mkdir( strPath ) == false )
    {
        berApplet->elog( QString( "fail to make path: %1").arg( strPath ) );
        ret = JSR_MAKE_DIR_FAIL;
        goto end;
    }

    strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    ret = JS_BIN_writePEM( pCert, JS_PEM_TYPE_CERTIFICATE, strCertPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->elog( QString( "fail to write certificate:%1" ).arg( strCertPath) );
        dir.rmdir( strPath );
        ret = JSR_FILE_WRITE_FAIL;
        goto end;
    }

    ret = JS_BIN_writePEM( pEncPriKey, JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY, strPriPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->elog( QString( "fail to write encrypted private key:%1" ).arg( strPriPath) );
        dir.rmpath( strPath );
        ret = JSR_FILE_WRITE_FAIL;
        goto end;
    }


    ret = JSR_OK;

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    return ret;
}

int CertManDlg::changePriKey( const BIN *pNewEncPriKey )
{
    int ret = -1;
    QDir dir;
    QString strPath = getSeletedPath();

    if( strPath.length() < 1 )
        return -1;

    strPath += "/";
    strPath += kPriKeyFile;

    dir.remove( strPath );
    ret = JS_BIN_fileWrite( pNewEncPriKey, strPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->elog( QString( "fail to write encrypted private key:%1" ).arg( strPath) );
        return JSR_FILE_WRITE_FAIL;
    }

    ret = JSR_OK;
    return ret;
}

const QString CertManDlg::getSeletedPath()
{
    QString strPath;

    QModelIndex idx = mEE_CertTable->currentIndex();
    QTableWidgetItem* item = mEE_CertTable->item( idx.row(), 0 );

    if( item ) strPath = item->data(Qt::UserRole).toString();

    return strPath;
}

const QString CertManDlg::getSeletedCertPath()
{
    QString strPath;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == TAB_EE_IDX )
    {
        QModelIndex idx = mEE_CertTable->currentIndex();
        QTableWidgetItem* item = mEE_CertTable->item( idx.row(), 0 );

        if( item )
        {
            QString strDir = item->data(Qt::UserRole).toString();
            strPath = QString( "%1/%2").arg( strDir ).arg( kCertFile );
        }
    }
    else if( nTabIdx == TAB_OTHER_IDX )
    {
        QModelIndex idx = mOther_CertTable->currentIndex();
        QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );

        if( item ) strPath = item->data(Qt::UserRole).toString();
    }

    return strPath;
}

const QString CertManDlg::getSelectedPriPath()
{
    QString strPath;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == TAB_EE_IDX )
    {
        QModelIndex idx = mEE_CertTable->currentIndex();
        QTableWidgetItem* item = mEE_CertTable->item( idx.row(), 0 );

        if( item )
        {
            QString strDir = item->data(Qt::UserRole).toString();
            strPath = QString( "%1/%2").arg( strDir ).arg( kPriKeyFile );
        }
    }

    return strPath;
}

const QString CertManDlg::getSeletedCAPath()
{
    QString strPath;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == TAB_CA_IDX )
    {
        QModelIndex idx = mCA_CertTable->currentIndex();
        QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );

        if( item ) strPath = item->data(Qt::UserRole).toString();
    }
    else if( nTabIdx == TAB_TRUST_IDX )
    {
        QModelIndex idx = mRCA_CertTable->currentIndex();
        QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );

        if( item ) strPath = item->data(Qt::UserRole).toString();
    }

    return strPath;
}

const QString CertManDlg::getSeletedCRLPath()
{
    QString strPath;

    QModelIndex idx = mCRL_Table->currentIndex();
    QTableWidgetItem* item = mCRL_Table->item( idx.row(), 0 );

    if( item ) strPath = item->data(Qt::UserRole).toString();

    return strPath;
}

int CertManDlg::readCA( const QString strCertPath, const BIN* pCert, BIN *pCA )
{
    int ret = 0;
    unsigned long uHash = 0;
    if( pCert == NULL ) return JSR_ERR;

    QString strCAPath;

    ret = JS_PKI_getIssuerNameHash( pCert, &uHash );
    if( ret != 0 ) return ret;

    strCAPath = QString( "%1/%2.0").arg( strCertPath ).arg( uHash );
    ret = JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), pCA );

    if( ret > 0 && pCA->nLen > 0 )
        ret = JSR_OK;
    else
        ret = JSR_ERR2;

    return ret;
}

int CertManDlg::writeNameHash( const QString strPath, const BIN *pCert )
{
    int i = 0;
    int ret = 0;
    unsigned long uHash = 0;
    if( pCert == NULL ) return JSR_ERR;

    QString strFilePath;
    QDir dir;
    int num = 0;

    if( dir.exists( strPath ) == false )
        dir.mkdir( strPath );

    ret = JS_PKI_getSubjectNameHash( pCert, &uHash );
    if( ret != 0 ) return ret;

    for( i = 0; i < 100; i++ )
    {
        strFilePath = QString( "%1/%2.%3").arg( strPath ).arg( uHash, 8, 16, QLatin1Char('0') ).arg( num + i );
        if( QFileInfo::exists( strFilePath ) == false ) break;
    }

    if( i >= 99 ) return -1;

    ret = JS_BIN_writePEM( pCert, JS_PEM_TYPE_CERTIFICATE, strFilePath.toLocal8Bit().toStdString().c_str() );

    return ret;
}

int CertManDlg::writeCRL( const QString strCRLPath, const BIN *pCRL )
{
    int ret = 0;
    int i = 0;
    unsigned long uHash = 0;
    if( pCRL == NULL ) return JSR_ERR;

    QString strFilePath;
    QDir dir;

    if( dir.exists( strCRLPath ) == false )
        dir.mkdir( strCRLPath );

    ret = JS_PKI_getCRLIssuerNameHash( pCRL, &uHash );
    if( ret != 0 ) return ret;

    while( i < 100 )
    {
        strFilePath = QString( "%1/%2.%3").arg( strCRLPath ).arg( uHash, 8, 16, QLatin1Char('0')  ).arg(i);
        if( QFileInfo::exists( strFilePath ) == false )
            break;
        i++;
    }

    if( i == 100 ) return JSR_ERR2;

    ret = JS_BIN_writePEM( pCRL, JS_PEM_TYPE_CRL, strFilePath.toLocal8Bit().toStdString().c_str() );

    return ret;
}

int CertManDlg::readPriKeyCert( BIN *pEncPriKey, BIN *pCert )
{
    int ret = 0;
    QString strPriPath;
    QString strCertPath;

    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return JSR_ERR;
    }

    strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pEncPriKey );
    if( ret <= 0 ) return JSR_ERR2;

    ret = JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), pCert );
    if( ret <= 0 ) return JSR_ERR3;

    return 0;
}

int CertManDlg::readCert( BIN *pCert )
{
    int ret = 0;
    QString strPath = getSeletedCertPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return JSR_ERR;
    }

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), pCert );
    if( ret <= 0 ) return JSR_ERR2;

    return 0;
}

int CertManDlg::readCACert( BIN *pCert )
{
    int ret = 0;
    QString strPath = getSeletedCAPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return JSR_ERR;
    }

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), pCert );
    if( ret <= 0 ) return JSR_ERR2;

    return 0;
}

int CertManDlg::readCRL( BIN *pCRL )
{
    int ret = 0;
    QString strPath = getSeletedCRLPath();
    if( strPath.length() < 1 )
    {
        berApplet->elog( QString( "There is no selected item" ) );
        return JSR_ERR;
    }

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), pCRL );
    if( ret <= 0 ) return JSR_ERR2;

    return 0;
}

void CertManDlg::clickViewCert()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    CertInfoDlg certInfo;

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret), this);
        goto end;
    }

    certInfo.setCertBIN( &binCert );
    certInfo.exec();

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickDeleteCert()
{
    int ret = 0;

    bool bVal = false;
    QDir dir;
    QString strCertPath;
    QString strPriKeyPath;

    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    bVal = berApplet->yesOrCancelBox( tr( "Are you sure to delete the certificate" ), this, false );
    if( bVal == false ) return;

    strCertPath = QString( "%1/%2" ).arg( strPath ).arg( kCertFile );
    strPriKeyPath = QString( "%1/%2" ).arg( strPath ).arg( kPriKeyFile );

    dir.remove( strCertPath );
    dir.remove( strPriKeyPath );
    dir.rmdir( strPath );

    loadEEList();
}

void CertManDlg::clickDecodeCert()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    QString strPath = getSeletedPath();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret ), this);
        goto end;
    }

    strPath += "/";
    strPath += kCertFile;

    berApplet->decodeData( &binCert, strPath );

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickDecodePriKey()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    QString strPath = getSeletedPath();

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret ), this);
        goto end;
    }

    strPath += "/";
    strPath += kPriKeyFile;
    berApplet->decodeData( &binEncPri, strPath );

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickCheckKeyPair()
{
    int ret = 0;

    BIN binPriKey = {0,0};
    BIN binEncPriKey = {0,0};
    BIN binCert = {0,0};

    QString strPass = mEE_PasswdText->text();

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        return;
    }

    ret = readPriKeyCert( &binEncPriKey, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "Please select a certificate [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( ret ), this );
        goto end;
    }

    ret = JS_PKI_IsValidPriKeyCert( &binPriKey, &binCert );
    if( ret == 1 )
    {
        berApplet->messageLog( tr( "The private key and ceritificate are good"), this );
    }
    else
    {
        berApplet->warnLog( tr( "The private key and certificate are bad" ), this );
    }

end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binCert );
}


void CertManDlg::clickImport()
{
    int ret = 0;

    QString strPass;
    PasswdDlg passwdDlg;
    QString strPFXFile;

    BIN binPFX = {0,0};
    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    strPFXFile = berApplet->findFile( this, JS_FILE_TYPE_PFX, strPFXFile );
    if( strPFXFile.length() < 1 ) return;

    JS_BIN_fileReadBER( strPFXFile.toLocal8Bit().toStdString().c_str(), &binPFX );

    if( passwdDlg.exec() != QDialog::Accepted )
        return;

    strPass = passwdDlg.mPasswdText->text();

    ret = JS_PKI_decodePFX( &binPFX, strPass.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg( JERR(ret) ), this);
        goto end;
    }

    ret = JS_PKI_encryptPrivateKey( -1, strPass.toStdString().c_str(), &binPri, NULL, &binEncPri );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to encrypt private key: %1").arg( JERR(ret) ), this );
        goto end;
    }

    ret = writePriKeyCert( &binEncPri, &binCert );
    if( ret == 0 )
    {
        loadEEList();
        berApplet->messageLog( tr( "The private key and certificate are saved successfully"), this );
    }
    else
    {
        berApplet->warnLog( tr( "fail to write private key and certificate: %1").arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binPFX );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickExport()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    QString strPass = mEE_PasswdText->text();

    QString strPFXPath;
    ExportDlg exportDlg;
    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password"), this );
        mEE_PasswdText->setFocus();
        return;
    }

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("Please select a certificate [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("fail to get certificate information [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPri, NULL, &binPri );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( JERR(ret) ), this );
        goto end;
    }

    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setPriKeyAndCert( &binPri, &binCert );
    exportDlg.exec();

    if( exportDlg.exec() == QDialog::Accepted )
    {
        berApplet->messageLog( tr( "PFX saved successfully:%1").arg( strPFXPath ), this );
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void CertManDlg::clickChangePasswd()
{
    int ret = 0;
    int nKeyType = -1;

    BIN binPriKey = {0,0};
    BIN binEncPriKey = {0,0};
    BIN binNewEncPriKey = {0,0};
    BIN binCert = {0,0};

    NewPasswdDlg newPasswd;
    QString strPass = mEE_PasswdText->text();

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mEE_PasswdText->setFocus();
        return;
    }

    ret = readPriKeyCert( &binEncPriKey, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "Please select a certificate [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( JERR(ret) ), this );
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binPriKey );

    if( newPasswd.exec() == QDialog::Accepted )
    {
        QString strNewPass = newPasswd.mPasswdText->text();

        ret = JS_PKI_encryptPrivateKey( -1, strNewPass.toStdString().c_str(), &binPriKey, NULL, &binNewEncPriKey );
        if( ret != 0 )
        {
            berApplet->warnLog( tr( "fail to encrypt private key: %1").arg( JERR(ret) ), this );
            goto end;
        }

        ret = changePriKey( &binNewEncPriKey );
        if( ret != 0 )
        {
            berApplet->warnLog( tr( "fail to change private key: %1").arg(JERR(ret) ), this );
            goto end;
        }

        berApplet->messageLog( tr( "The private key password is changed successfully" ), this );
    }


end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binNewEncPriKey );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickViewPriKey()
{
    int ret = 0;

    BIN binPriKey = {0,0};
    BIN binEncPriKey = {0,0};
    BIN binCert = {0,0};
    PriKeyInfoDlg priKeyInfo;

    QString strPass = mEE_PasswdText->text();

    if( strPass.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mEE_PasswdText->setFocus();
        return;
    }

    ret = readPriKeyCert( &binEncPriKey, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "Please select a certificate [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt private key: %1").arg( JERR(ret) ), this );
        goto end;
    }

    priKeyInfo.setPrivateKey( &binPriKey );
    priKeyInfo.exec();

    if( berApplet->settingsMgr()->supportKeyPairChange() == true )
    {
        BIN binRead = {0,0};
        BIN binEnc = {0,0};
        priKeyInfo.readPrivateKey( &binRead );

        if( JS_BIN_cmp( &binRead, &binPriKey ) != 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
            if( bVal == true )
            {
                ret = JS_PKI_encryptPrivateKey2( -1, strPass.toStdString().c_str(), &binRead, NULL, &binEnc );
                if( ret == 0 )
                {
                    ret = writePriKeyCert( &binEnc, &binCert );
                    berApplet->messageLog( tr( "Key change saved." ), this );
                }
            }
        }

        JS_BIN_reset( &binRead );
        JS_BIN_reset( &binEnc );
    }

end :
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickViewPubKey()
{
    int ret = 0;
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    BIN binPub = {0,0};
    PriKeyInfoDlg priKeyInfo;

    ret = readPriKeyCert( &binEncPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret ), this);
        goto end;
    }

    ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
    if( ret != 0 ) goto end;

    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
}

void CertManDlg::clickRunSign()
{
    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no selected item" ), this );
        return;
    }

    QString strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    QString strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    berApplet->mainWindow()->runSignVerify( true, true, strPriPath, strCertPath );
}

void CertManDlg::clickRunVerify()
{
    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no selected item" ), this );
        return;
    }

    QString strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    QString strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    berApplet->mainWindow()->runSignVerify( false, true, strPriPath, strCertPath );
}

void CertManDlg::clickRunPubEnc()
{
    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no selected item" ), this );
        return;
    }

    QString strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    QString strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    int nKeyType = -1;
    BIN binCert = {0,0};

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    nKeyType = JS_PKI_getCertKeyType( &binCert );
    JS_BIN_reset( &binCert );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr( "This key does not support public key encryption" ), this );
        return;
    }

    berApplet->mainWindow()->runPubEncDec( true, true, strPriPath, strCertPath );
}

void CertManDlg::clickRunPubDec()
{
    QString strPath = getSeletedPath();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no selected item" ), this );
        return;
    }

    QString strPriPath = QString("%1/%2").arg( strPath ).arg( kPriKeyFile );
    QString strCertPath = QString("%1/%2").arg( strPath ).arg( kCertFile );

    int nKeyType = -1;
    BIN binCert = {0,0};

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    nKeyType = JS_PKI_getCertKeyType( &binCert );
    JS_BIN_reset( &binCert );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr( "This key does not support public key encryption" ), this );
        return;
    }

    berApplet->mainWindow()->runPubEncDec( false, true, strPriPath, strCertPath );
}

void CertManDlg::clickOK()
{
    int ret = 0;

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &cert_ );
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_reset( &crl_ );

    if( mode_ == ManModeBase )
    {
        QDialog::accept();
        return;
    }

    BIN binEncPriKey = {0,0};
    BIN binCert = {0,0};
    BIN binCRL = {0,0};
    BIN binPriKey = {0,0};

    if( mode_ == ManModeSelCert )
    {
        if( mEE_CertTable->rowCount() < 1 && mOther_CertTable->rowCount() < 1 )
        {
            QDialog::reject();
            return;
        }

        ret = readCert( &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret), this );
            goto end;
        }

        JS_BIN_copy( &cert_, &binCert );
    }
    else if( mode_ == ManModeSelCA )
    {
        if( mCA_CertTable->rowCount() < 1 && mRCA_CertTable->rowCount() < 1 )
        {
            QDialog::reject();
            return;
        }

        ret = readCACert( &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Please select a CA certificate [%1]" ).arg(ret), this );
            goto end;
        }

        JS_BIN_copy( &ca_cert_, &binCert );
    }
    else if( mode_ == ManModeSelCRL )
    {
        if( mCRL_Table->rowCount() < 1 )
        {
            QDialog::reject();
            return;
        }

        ret = readCRL( &binCRL );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Please select a CRL [%1]" ).arg(ret), this );
            goto end;
        }

        JS_BIN_copy( &crl_, &binCRL );
    }
    else
    {
        QString strPass = mEE_PasswdText->text();
        if( mEE_CertTable->rowCount() < 1 )
        {
            QDialog::reject();
            return;
        }

        if( strPass.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mEE_PasswdText->setFocus();
            return;
        }

        ret = readPriKeyCert( &binEncPriKey, &binCert );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "Please select a certificate [%1]" ).arg(ret), this );
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPriKey, NULL, &binPriKey );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt the private key: %1" ).arg( JERR(ret) ), this );
            goto end;
        }

        JS_BIN_copy( &pri_key_, &binPriKey );
        JS_BIN_copy( &cert_, &binCert );
    }

end :
    JS_BIN_reset( &binEncPriKey );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binPriKey );

    if( ret == 0 )  QDialog::accept();
}

void CertManDlg::clickAddCA()
{
    int ret = 0;
    int bSelfSign = 0;
    unsigned long uHash = 0;

    BIN binCA = {0,0};
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtList = NULL;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    QString strCAPath = berApplet->settingsMgr()->CACertPath();

    QDir dir;

    if( dir.exists( strCAPath ) == false )
    {
        if( dir.mkdir( strCAPath ) == false )
        {
            berApplet->warningBox( tr( "fail to make other folder: %1").arg( strCAPath ), this );
            return;
        }
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( fileName.length() > 0 )
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCA );
        ret = JS_PKI_getCertInfo2( &binCA, &sCertInfo, &pExtList, &bSelfSign );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getSubjectNameHash( &binCA, &uHash );
        if( ret != 0 ) goto end;

        QString strBC = CertInfoDlg::getValueFromExtList( kExtNameBC, pExtList );
        QString strFileName = QString( "%1.0" ).arg( uHash, 8, 16, QLatin1Char('0'));
        QString strSaveName = QString( "%1/%2" ).arg( strCAPath ).arg( strFileName );

        if( CertInfoDlg::isCA( strBC ) == false )
        {
            berApplet->warningBox( tr( "This certificate is not CA certificate"), this );
            goto end;
        }

        if( QFileInfo::exists( strFileName ) == true )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed").arg( strSaveName ), this );
            goto end;
        }

        ret = writeNameHash( strCAPath, &binCA );
        if( ret > 0 )
        {
            loadCAList();
            berApplet->messageBox( tr( "The Certificate saved to CA folder"), this );
        }
        else
        {
            berApplet->warningBox( tr( "The Certificate failed to save to CA folder:%1" ).arg(JERR(ret)), this );
        }
    }

end :
    JS_BIN_reset( &binCA );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );
}

void CertManDlg::clickRemoveCA()
{
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CA certificate" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Do you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
    {
        loadCAList();
        berApplet->messageBox( tr( "The CA has been deleted"), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete the CA" ), this );
        return;
    }

}

void CertManDlg::clickViewCA()
{
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CA certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    CertInfoDlg certInfo;
    certInfo.setCertPath( strPath );
    certInfo.exec();
}

void CertManDlg::clickDecodeCA()
{
    BIN binCert = {0,0};
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CA certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    berApplet->decodeData( &binCert, strPath );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickViewPubKeyCA()
{
    BIN binCert = {0,0};
    BIN binPub = {0,0};

    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CA certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();
    PriKeyInfoDlg priKeyInfo;

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    int ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
    if( ret != 0 ) goto end;

    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
}

void CertManDlg::clickExportCA()
{
    BIN binCert = {0,0};
    QModelIndex idx = mCA_CertTable->currentIndex();

    QTableWidgetItem* item = mCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CA certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();
    ExportDlg exportDlg;
    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binCert );
    exportDlg.exec();

    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binCert );

}

void CertManDlg::clickAddOther()
{
    int ret = 0;
    int bSelfSign = 0;
    unsigned long uHash = 0;

    BIN binOther = {0,0};
    JCertInfo sCertInfo;
    JExtensionInfoList *pExtList = NULL;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    QString strOtherPath = berApplet->settingsMgr()->otherCertPath();

    QDir dir;

    if( dir.exists( strOtherPath ) == false )
    {
        if( dir.mkdir( strOtherPath ) == false )
        {
            berApplet->warningBox( tr( "fail to make other folder: %1").arg( strOtherPath ), this );
            return;
        }
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( fileName.length() > 0 )
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binOther );
        ret = JS_PKI_getCertInfo2( &binOther, &sCertInfo, &pExtList, &bSelfSign );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getSubjectNameHash( &binOther, &uHash );
        if( ret != 0 ) goto end;

        QString strFileName = QString( "%1.0" ).arg( uHash, 8, 16, QLatin1Char('0'));
        QString strSaveName = QString( "%1/%2" ).arg( strOtherPath ).arg( strFileName );

        if( QFileInfo::exists( strFileName ) == true )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed").arg( strSaveName ), this );
            goto end;
        }

        ret = writeNameHash( strOtherPath, &binOther );
        if( ret > 0 )
        {
            loadOtherList();
            berApplet->messageBox( tr( "The Certificate saved to other folder"), this );
        }
        else
        {
            berApplet->warningBox( tr( "The Certificate failed to save to other folder:%1" ).arg(JERR(ret)), this );
        }
    }

end :
    JS_BIN_reset( &binOther );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );
}

void CertManDlg::clickRemoveOther()
{
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Do you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
    {
        loadOtherList();
        berApplet->messageBox( tr( "The certificate has been deleted"), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete the certificate" ), this );
        return;
    }

}

void CertManDlg::clickViewOther()
{
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    CertInfoDlg certInfo;
    certInfo.setCertPath( strPath );
    certInfo.exec();
}

void CertManDlg::clickDecodeOther()
{
    BIN binCert = {0,0};
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    berApplet->decodeData( &binCert, strPath );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickViewPubKeyOther()
{
    BIN binCert = {0,0};
    BIN binPub = {0,0};

    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();
    PriKeyInfoDlg priKeyInfo;

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    int ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
    if( ret != 0 ) goto end;

    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
}

void CertManDlg::clickExportOther()
{
    BIN binCert = {0,0};
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();
    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );

    ExportDlg exportDlg;
    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binCert );
    exportDlg.exec();

    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickRunVerifyOther()
{
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    berApplet->mainWindow()->runSignVerify( false, true, "", strPath );
}

void CertManDlg::clickRunPubEncOther()
{
    QModelIndex idx = mOther_CertTable->currentIndex();

    QTableWidgetItem* item = mOther_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a certificate" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    int nKeyType = -1;
    BIN binCert = {0,0};

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    nKeyType = JS_PKI_getCertKeyType( &binCert );
    JS_BIN_reset( &binCert );

    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr( "This key does not support public key encryption" ), this );
        return;
    }

    berApplet->mainWindow()->runPubEncDec( true, true, "", strPath );
}

void CertManDlg::clickAddCRL()
{
    int ret = 0;
    int bSelfSign = 0;
    unsigned long uHash = 0;

    BIN binCRL = {0,0};
    JCRLInfo sCRLInfo;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CRL, strPath );
    QString strCRLPath = berApplet->settingsMgr()->CRLPath();

    QDir dir;

    if( dir.exists( strCRLPath ) == false )
    {
        if( dir.mkdir( strCRLPath ) == false )
        {
            berApplet->warningBox( tr( "fail to make CRL folder: %1").arg( strCRLPath ), this );
            return;
        }
    }

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    if( fileName.length() > 0 )
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCRL );
        ret = JS_PKI_getCRLInfo( &binCRL, &sCRLInfo, NULL, NULL );
        if( ret != 0 ) goto end;

        ret = writeCRL( strCRLPath, &binCRL );
        if( ret > 0 )
        {
            loadCRLList();
            berApplet->messageBox( tr( "The CRL saved to CRL folder"), this );
        }
        else
        {
            berApplet->warningBox( tr( "The CRL failed to save to CRL folder:%1" ).arg(JERR(ret)), this );
        }
    }

end :
    JS_BIN_reset( &binCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
}

void CertManDlg::clickRemoveCRL()
{
    QModelIndex idx = mCRL_Table->currentIndex();

    QTableWidgetItem* item = mCRL_Table->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CRL" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Do you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
    {
        loadCAList();
        berApplet->messageBox( tr( "The CRL has been deleted"), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete the CRL" ), this );
        return;
    }
}

void CertManDlg::clickViewCRL()
{
    QModelIndex idx = mCRL_Table->currentIndex();

    QTableWidgetItem* item = mCRL_Table->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CRL" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    CRLInfoDlg crlInfo;
    crlInfo.setCRLPath( strPath );
    crlInfo.exec();
}

void CertManDlg::clickDecodeCRL()
{
    BIN binCRL = {0,0};
    QModelIndex idx = mCRL_Table->currentIndex();

    QTableWidgetItem* item = mCRL_Table->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CRL" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCRL );
    berApplet->decodeData( &binCRL, strPath );
    JS_BIN_reset( &binCRL );
}

void CertManDlg::clickExportCRL()
{
    BIN binCRL = {0,0};
    QModelIndex idx = mCRL_Table->currentIndex();

    QTableWidgetItem* item = mCRL_Table->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a CRL" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCRL );

    ExportDlg exportDlg;
    JCRLInfo sCRLInfo;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    JS_PKI_getCRLInfo( &binCRL, &sCRLInfo, NULL, NULL );

    exportDlg.setName( sCRLInfo.pIssuerName );
    exportDlg.setCRL( &binCRL );
    exportDlg.exec();

    JS_PKI_resetCRLInfo( &sCRLInfo );
    JS_BIN_reset( &binCRL );
}

void CertManDlg::clickAddTrust()
{
    int ret = 0;
    int bSelfSign = 0;
    unsigned long uHash = 0;

    BIN binCA = {0,0};
    JCertInfo sCertInfo;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    QString strTrustPath = berApplet->settingsMgr()->trustCertPath();

    QDir dir;

    if( dir.exists( strTrustPath ) == false )
    {
        if( dir.mkdir( strTrustPath ) == false )
        {
            berApplet->warningBox( tr( "fail to make TrustCA folder: %1").arg( strTrustPath ), this );
            return;
        }
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( fileName.length() > 0 )
    {
        JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCA );
        ret = JS_PKI_getCertInfo2( &binCA, &sCertInfo,NULL, &bSelfSign );
        if( ret != 0 ) goto end;

        if( bSelfSign == 0 )
        {
            berApplet->warningBox( tr( "This certificate is not self-signed"), this );
            goto end;
        }

        ret = JS_PKI_getSubjectNameHash( &binCA, &uHash );
        if( ret != 0 ) goto end;

        QString strFileName = QString( "%1.0" ).arg( uHash, 8, 16, QLatin1Char('0'));
        QString strSaveName = QString( "%1/%2" ).arg( strTrustPath ).arg( strFileName );
        if( QFileInfo::exists( strFileName ) == true )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed").arg( strSaveName ), this );
            goto end;
        }

        ret = JS_BIN_writePEM( &binCA, JS_PEM_TYPE_CERTIFICATE, strSaveName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            loadTrustList();
            berApplet->messageBox( tr( "The Certificate saved to trustedCA folder"), this );
        }
        else
        {
            berApplet->warningBox( tr( "The Certificate failed to save to trustedCA folder:%1" ).arg(JERR(ret)), this );
        }
    }

end :
    JS_BIN_reset( &binCA );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void CertManDlg::clickRemoveTrust()
{
    QModelIndex idx = mRCA_CertTable->currentIndex();

    QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a Trust RootCA" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Do you delete?"), this, false );
    if( bVal == false ) return;

    const QString strPath = item->data( Qt::UserRole ).toString();
    QFile delFile( strPath );
    bVal = delFile.remove();

    if( bVal == true )
    {
        loadTrustList();
        berApplet->messageBox( tr( "Trust CA has been deleted"), this );
    }
    else
    {
        berApplet->warningBox( tr( "failed to delete Trust CA" ), this );
        return;
    }

}

void CertManDlg::clickViewTrust()
{
    QModelIndex idx = mRCA_CertTable->currentIndex();

    QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a Trust RootCA" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    CertInfoDlg certInfo;
    certInfo.setCertPath( strPath );
    certInfo.exec();
}

void CertManDlg::clickDecodeTrust()
{
    BIN binCert = {0,0};
    QModelIndex idx = mRCA_CertTable->currentIndex();

    QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a Trust RootCA" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    berApplet->decodeData( &binCert, strPath );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickViewPubKeyTrust()
{
    BIN binCert = {0,0};
    BIN binPub = {0,0};

    QModelIndex idx = mRCA_CertTable->currentIndex();

    QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a Trust RootCA" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();
    PriKeyInfoDlg priKeyInfo;

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    int ret = JS_PKI_getPubKeyFromCert( &binCert, &binPub );
    if( ret != 0 ) goto end;

    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
}

void CertManDlg::clickExportTrust()
{
    BIN binCert = {0,0};
    QModelIndex idx = mRCA_CertTable->currentIndex();

    QTableWidgetItem* item = mRCA_CertTable->item( idx.row(), 0 );
    if( item == NULL )
    {
        berApplet->warningBox( tr( "Please select a Trust RootCA" ), this );
        return;
    }

    const QString strPath = item->data( Qt::UserRole ).toString();

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binCert );
    ExportDlg exportDlg;
    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binCert );
    exportDlg.exec();

    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binCert );
}

void CertManDlg::decodeTLPriKey()
{
    BIN binData = {0,0};
    QString strFile = mTLPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find Private Key" ), this );
        mTLPriKeyPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void CertManDlg::decodeTLCert()
{
    BIN binData = {0,0};
    QString strFile = mTLCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        mTLCertPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void CertManDlg::decodeTLPFX()
{
    BIN binData = {0,0};
    QString strFile = mTLPFXPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a PFX" ), this );
        mTLPFXPathText->setFocus();
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void CertManDlg::clearTLPriKey()
{
    mTLPriKeyPathText->clear();
}

void CertManDlg::clearTLCert()
{
    mTLCertPathText->clear();
}

void CertManDlg::clearTLPFX()
{
    mTLPFXPathText->clear();
}

void CertManDlg::findTLPriKey()
{
    QString strPath = mTLPriKeyPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 )
    {
        mTLPriKeyPathText->setText( filePath );
    }
}

void CertManDlg::findTLCert()
{
    QString strPath = mTLCertPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mTLCertPathText->setText( filePath );
    }
}

void CertManDlg::findTLPFX()
{
    QString strPath = mTLPFXPathText->text();


    QString filePath = berApplet->findFile( this, JS_FILE_TYPE_PFX, strPath );
    if( filePath.length() > 0 )
    {
        mTLPFXPathText->setText( filePath );
    }
}

void CertManDlg::checkTLEncPriKey()
{
    bool bVal = mTLEncPriKeyCheck->isChecked();

    if( bVal == true )
        mTLPriKeyLabel->setText( tr("EncPrivateKey") );
    else
        mTLPriKeyLabel->setText( tr("PrivateKey" ) );
}

void CertManDlg::clickTLCheckKeyPair()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    QString strPriPath = mTLPriKeyPathText->text();
    QString strCertPath = mTLCertPathText->text();


    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find private key"), this );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find public key or certificate" ), this );
        return;
    }

    if( mTLEncPriKeyCheck->isChecked() )
    {
        PasswdDlg passDlg;
        QString strPass;

        passDlg.setTitle( tr("Enter private key password") );

        if( passDlg.exec() != QDialog::Accepted )
            goto end;

        strPass = passDlg.mPasswdText->text();

        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binEncPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "fail to read encrypted private key: %1").arg( JERR(ret)), this );
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPri, NULL, &binPri );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt the private key: %1").arg( JERR(ret) ), this );
            goto end;
        }
    }
    else
    {
        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "fail to read private key: %1").arg( JERR(ret)), this );
            goto end;
        }
    }

    ret = JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to read certificate: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_IsValidPriKeyCert( &binPri, &binCert );

    if( ret == JSR_VALID )
        berApplet->messageBox( tr("The private key and the certificate are correct"), this );
    else
        berApplet->warningBox( QString( tr("The private key and the certificate are incorrect [%1]").arg(ret) ), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickTLViewCert()
{
    int ret = -1;
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mTLCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void CertManDlg::clickTLEncryptPFX()
{
    int ret = 0;

    int nPBE = 0;
    int nKeyType = -1;

    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};
    BIN binPFX = {0,0};

    QString strPriPath = mTLPriKeyPathText->text();
    QString strCertPath = mTLCertPathText->text();
    QString strPFXPath;

    QString strSN = mTLModeCombo->currentText();
    QString strPFXPasswd = mTLPasswdText->text();

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find private key"), this );
        return;
    }

    if( strCertPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    QFileInfo certInfo( strCertPath );

    if( strPFXPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mTLPasswdText->setFocus();
        return;
    }

    if( mTLEncPriKeyCheck->isChecked() )
    {
        PasswdDlg passDlg;
        QString strPass;

        passDlg.setTitle( tr("Enter private key password") );

        if( passDlg.exec() != QDialog::Accepted )
            goto end;

        strPass = passDlg.mPasswdText->text();

        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binEncPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to read encrypted private key: %1" ).arg( JERR(ret)), this );
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPri, NULL, &binPri );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt the private key: %1").arg( JERR(ret) ), this );
            goto end;
        }
    }
    else
    {
        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to read private key: %1" ).arg( JERR(ret)), this );
            goto end;
        }
    }

    ret = JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read certificate: %1" ).arg( JERR(ret)), this );
        goto end;
    }

    nPBE = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
    nKeyType = JS_PKI_getPriKeyType( &binPri );

    ret = JS_PKI_encodePFX( &binPFX, strPFXPasswd.toStdString().c_str(), nPBE, &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to make PFX: %1").arg(ret), this);
        goto end;
    }

    strPFXPath = QString( "%1/%2_p12.pfx" ).arg( certInfo.path() ).arg( certInfo.baseName() );

    ret = JS_BIN_fileWrite( &binPFX, strPFXPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to write pfx: %1" ).arg(ret ), this );
        goto end;
    }

    berApplet->messageLog( tr( "PFX encrypt successfully(%1)" ).arg( strPFXPath ), this );
    mTLPFXPathText->setText( strPFXPath );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPFX );
}

void CertManDlg::clickTLDecryptPFX()
{
    int ret = 0;
    int nKeyType = -1;
    BIN binData = {0,0};
    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    QString strFile = mTLPFXPathText->text();
    QString strPasswd = mTLPasswdText->text();

    QString strPriKeyPath;
    QString strCertPath;

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find PFX" ), this );
        return;
    }

    QFileInfo pfxInfo( strFile );

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mTLPasswdText->setFocus();
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_decodePFX( &binData, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg(JERR(ret)), this);
        goto end;
    }

    if( mTLEncPriKeyCheck->isChecked() )
    {
        NewPasswdDlg newPass;
        QString strPass;
        newPass.setTitle( tr( "Enter a new private key password" ));

        if( newPass.exec() != QDialog::Accepted )
            goto end;

        nKeyType = JS_PKI_getPriKeyType( &binPri );

        strPass = newPass.mPasswdText->text();
        ret = JS_PKI_encryptPrivateKey( -1, strPass.toStdString().c_str(), &binPri, NULL, &binEncPri );
        if( ret != 0 )
        {
            berApplet->warnLog( tr( "fail to encrypt private key: %1").arg( JERR(ret) ), this);
            goto end;
        }

        strPriKeyPath = QString( "%1/%2_prikey.key" ).arg( pfxInfo.path() ).arg( pfxInfo.baseName() );
        ret = JS_BIN_fileWrite( &binEncPri, strPriKeyPath.toLocal8Bit().toStdString().c_str() );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "fail to write encrypted private key: %1").arg(JERR(ret)), this );
            goto end;
        }
    }
    else
    {
        strPriKeyPath = QString( "%1/%2_prikey.der" ).arg( pfxInfo.path() ).arg( pfxInfo.baseName() );
        ret = JS_BIN_fileWrite( &binPri, strPriKeyPath.toLocal8Bit().toStdString().c_str() );
        if( ret <= 0 )
        {
            berApplet->warningBox( tr( "fail to write private key: %1").arg(JERR(ret)), this );
            goto end;
        }
    }

    strCertPath = QString( "%1/%2_cert.der" ).arg( pfxInfo.path() ).arg( pfxInfo.baseName() );
    ret = JS_BIN_fileWrite( &binCert, strCertPath.toLocal8Bit().toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to write certificate: %1").arg(JERR(ret)), this );
        goto end;
    }


    mTLPriKeyPathText->setText( strPriKeyPath );
    mTLCertPathText->setText( strCertPath );

    berApplet->messageLog( tr( "PFX decrypt successfully" ), this );

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickTLSavePFX()
{
    int ret = 0;
    int nKeyType = -1;

    BIN binPFX = {0,0};
    BIN binPri = {0,0};
    BIN binEncPri = {0,0};
    BIN binCert = {0,0};

    QString strFile = mTLPFXPathText->text();
    QString strPasswd = mTLPasswdText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find PFX" ), this );
        return;
    }

    QFileInfo pfxInfo( strFile );

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a password" ), this );
        mTLPasswdText->setFocus();
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binPFX );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read PFX: %1" ).arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_decodePFX( &binPFX, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to decrypt PFX: %1").arg(JERR(ret)), this);
        goto end;
    }

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    ret = JS_PKI_encryptPrivateKey( -1, strPasswd.toStdString().c_str(), &binPri, NULL, &binEncPri );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "fail to encrypt private key: %1").arg( JERR(ret) ), this );
        goto end;
    }

    ret = writePriKeyCert( &binEncPri, &binCert );
    if( ret == JSR_OK )
    {
        loadEEList();
        berApplet->messageLog( tr( "The private key and certificate are saved successfully"), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to write private and certificate: %1" ).arg( JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binPFX );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );
    JS_BIN_reset( &binCert );
}

void CertManDlg::clickTLViewPriKey()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binEncPri = {0,0};

    QString strPriPath = mTLPriKeyPathText->text();
    PriKeyInfoDlg priKeyInfo;

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find private key"), this );
        return;
    }


    if( mTLEncPriKeyCheck->isChecked() )
    {
        PasswdDlg passDlg;
        QString strPass;

        passDlg.setTitle( tr("Enter private key password") );

        if( passDlg.exec() != QDialog::Accepted )
            goto end;

        strPass = passDlg.mPasswdText->text();

        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binEncPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binEncPri, NULL, &binPri );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "fail to decrypt the private key: %1").arg( ret ), this );
            goto end;
        }
    }
    else
    {
        ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
        if( ret < 0 )
        {
            berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
            goto end;
        }
    }

    priKeyInfo.setPrivateKey( &binPri );
    priKeyInfo.exec();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binEncPri );

}

void CertManDlg::clickTLViewPubKey()
{
    int ret = -1;
    PriKeyInfoDlg priKeyInfo;
    BIN binData = {0,0};
    QString strFile = mTLCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    ret = JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "failed to read : %1" ).arg( JERR(ret)), this );
        return;
    }

    priKeyInfo.setPublicKey( &binData );
    priKeyInfo.exec();

    JS_BIN_reset( &binData );
}
