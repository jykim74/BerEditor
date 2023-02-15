#include "cert_pvd_dlg.h"
#include "js_pki.h"
#include "js_pki_pvd.h"
#include "js_util.h"
#include "common.h"

#include "ber_applet.h"
#include "mainwindow.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"

const QStringList kParamList = { "Policy", "Purpose", "Name", "Depth", "AuthLevel", "HostName", "Email", "IP" };

CertPVDDlg::CertPVDDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mTrustFindBtn, SIGNAL(clicked()), this, SLOT(clickTrustFind()));
    connect( mUntrustFindBtn, SIGNAL(clicked()), this, SLOT(clickUntrustFind()));
    connect( mCRLFindBtn, SIGNAL(clicked()), this, SLOT(clickCRLFind()));
    connect( mTargetFindBtn, SIGNAL(clicked()), this, SLOT(clickTargetFind()));
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
    connect( mCertVerifyBtn, SIGNAL(clicked()), this, SLOT(clickCertVerify()));

    connect( mUseCheckTimeCheck, SIGNAL(clicked()), this, SLOT(checkUseCheckTime()));
    connect( mParamAddBtn, SIGNAL(clicked()), this, SLOT(clickParamAdd()));
    connect( mParamListClearBtn, SIGNAL(clicked()), this, SLOT(clickParamListClear()));

    initialize();
}

CertPVDDlg::~CertPVDDlg()
{

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
    mPathTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPathTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sParamLabels = { tr( "Param"), tr( "Value" ) };

    mParamTable->clear();
    mParamTable->horizontalHeader()->setStretchLastSection(true);
    mParamTable->setColumnCount(2);
    mParamTable->setHorizontalHeaderLabels( sParamLabels );
    mParamTable->verticalHeader()->setVisible(false);
    mParamTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mParamTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mParamTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QDateTime dateTime = QDateTime::currentDateTime();
    mVerifyDateTime->setDateTime(dateTime);

    mParamCombo->addItems( kParamList );

    checkUseCheckTime();
}

void CertPVDDlg::clickTrustFind()
{
    QString strPath = mTrustPathText->text();

    if( strPath.length() < 1 ) strPath = "D:\pvd_certs";

    QString strFile = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
        mTrustPathText->setText( strFile );
}

void CertPVDDlg::clickUntrustFind()
{
    QString strPath = mUntrustPathText->text();

    if( strPath.length() < 1 ) strPath = "D:\pvd_certs";

    QString strFile = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
        mUntrustPathText->setText( strFile );
}

void CertPVDDlg::clickCRLFind()
{
    QString strPath = mCRLPathText->text();

    if( strPath.length() < 1 ) strPath = "D:\pvd_certs";

    QString strFile = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
        mCRLPathText->setText( strFile );
}

void CertPVDDlg::clickTargetFind()
{
    QString strPath = mTargetPathText->text();

    if( strPath.length() < 1 ) strPath = "D:\pvd_certs";

    QString strFile = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( strFile.length() > 0 )
        mTargetPathText->setText( strFile );
}

void CertPVDDlg::clickCertVerify()
{
    int ret = 0;
    char sMsg[1024];

    BIN binTrust = {0,0};
    BIN binUntrust = {0,0};
    BIN binCRL = {0,0};

    QString strTrustPath = mTrustPathText->text();
    QString strUntrustPath = mUntrustPathText->text();
    QString strCLRPath = mCRLPathText->text();

    if( strTrustPath.length() > 1 )
    {
        JS_BIN_fileRead( strTrustPath.toLocal8Bit().toStdString().c_str(), &binTrust );
    }

    if( strUntrustPath.length() > 1 )
    {
        JS_BIN_fileRead( strUntrustPath.toLocal8Bit().toStdString().c_str(), &binUntrust );
    }
    else
    {
        berApplet->warningBox( "You have to find untrust certificate", this );
        goto end;
    }

    if( strCLRPath.length() > 1 )
    {
        JS_BIN_fileRead( strCLRPath.toLocal8Bit().toStdString().c_str(), &binCRL );
    }

    ret = JS_PKI_PVDCertValid( &binTrust, &binCRL, &binUntrust, sMsg );

    berApplet->log( QString( "PVDCertValid : %1").arg(ret));
    if( ret == 1 )
    {
        QString strOK = "The untrust certificate is OK";
        berApplet->log( strOK );
        berApplet->messageBox( strOK, this );
    }
    else
    {
        QString strErr = QString( "The untrust certificate verify fail: %1" ).arg(sMsg);
        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
    }

    ret = JS_PKI_verifyCert( &binTrust, &binCRL, &binUntrust, sMsg );
    berApplet->log( QString( "verifyCert : %1").arg(ret));
    if( ret != 1 ) berApplet->elog( QString("verify error msg: %1").arg(sMsg));

end :
    JS_BIN_reset( &binTrust );
    JS_BIN_reset( &binUntrust );
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
    time_t tCheckTime = 0;

    QString strTrustPath = mTrustPathText->text();
    QString strUntrustPath = mUntrustPathText->text();
    QString strCLRPath = mCRLPathText->text();
    QString strTargetPath = mTargetPathText->text();

    JNumValList *pParamList = NULL;

    char sMsg[1024];
    int nCount = 0;
    int nFlags = 0;

    if( strTrustPath.length() > 1 )
    {
        JS_BIN_fileRead( strTrustPath.toLocal8Bit().toStdString().c_str(), &binTrust );
        JS_BIN_addList( &pTrustList, &binTrust );
        JS_BIN_reset( &binTrust );
    }

    if( strUntrustPath.length() > 1 )
    {
        JS_BIN_fileRead( strUntrustPath.toLocal8Bit().toStdString().c_str(), &binUntrust );
        JS_BIN_addList( &pTrustList, &binUntrust );
        JS_BIN_reset( &binUntrust );
    }

    if( strCLRPath.length() > 1 )
    {
        JS_BIN_fileRead( strCLRPath.toLocal8Bit().toStdString().c_str(), &binCRL );
        JS_BIN_addList( &pCRLList, &binCRL );
        JS_BIN_reset( &binCRL );
    }

    if( strTargetPath.length() < 1 )
    {
        berApplet->warningBox( tr( "You have to find target certificate" ), this );
        goto end;
    }

    JS_BIN_fileRead( strTargetPath.toLocal8Bit().toStdString().c_str(), &binTarget );

    nCount = mPathTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        BIN binData = {0,0};
        QString strType = mPathTable->item( i, 0 )->text();
        QString strPath = mPathTable->item( i, 1 )->text();

        JS_BIN_fileRead( strPath.toLocal8Bit().toStdString().c_str(), &binData );

        if( strType == "Trust" )
        {
            JS_BIN_addList( &pTrustList, &binData );
        }
        else if( strType == "Untrust" )
        {
            JS_BIN_addList( &pUntrustList, &binData );
        }
        else if( strType == "CRL" )
        {
            JS_BIN_addList( &pCRLList, &binData );
        }

        JS_BIN_reset( &binData );
    }

    if( mUseCheckTimeCheck->isChecked() )
    {
        QString strValue = QString( "%1" ).arg( mVerifyDateTime->dateTime().toTime_t() );
        _addParamValue( &pParamList, JS_PVD_FLAG_USE_CHECK_TIME, strValue.toStdString().c_str() );
    }

    if( mCRLCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CRL_CHECK );
    if( mIgnoreCriticalCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_IGNORE_CRITICAL );
    if( mX509StrictCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_X509_STRICT );
    if( mAllowProxyCertsCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_ALLOW_PROXY_CERTS );
    if( mPolicyCheckCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_POLICY_CHECK );
    if( mExplicitPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXPLICIT_POLICY );
    if( mInhibitAnyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_ANY );
    if( mInhibitMapCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_INHIBIT_MAP );
    if( mNotifyPolicyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_NOTIFY_POLICY );
    if( mExtendedCRLSupportCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_EXTENDED_CRL_SUPPORT );
    if( mUseDeltasCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_USE_DELTAS );
    if( mCheckSSSignatureCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_CHECK_SS_SIGNATURE );
    if( mTrustedFirstCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_TRUSTED_FIRST );
    if( mSuiteB128LosOnlyCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS_ONLY );
    if( mSuiteB192LosCheck->isChecked() ) _addParamFlag( &pParamList,JS_PVD_FLAG_SUITEB_192_LOS );
    if( mSuiteB128LogCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_SUITEB_128_LOS );
    if( mPartialChainCheck->isChecked() ) _addParamFlag( &pParamList, JS_PVD_FLAG_PARTIAL_CHAIN );

    nCount = mParamTable->rowCount();
    for( int i = 0; i < nCount; i++ )
    {
        int nID = 0;
        QString strParam = mPathTable->item( i, 0 )->text();
        QString strValue = mPathTable->item( i, 1 )->text();

        nID = _getParamID( strParam );
        if( nID < 0 ) continue;

        _addParamValue( &pParamList, nID, strValue.toStdString().c_str() );
    }

    tCheckTime = mVerifyDateTime->dateTime().toTime_t();
    ret = JS_PKI_CertPVD( pTrustList, pUntrustList, pCRLList, pParamList, &binTarget, sMsg );

    berApplet->log( QString( "PVDCertValid : %1").arg(ret));
    if( ret == 1 )
    {
        QString strOK = "The PathValidation of the target certificate is OK";
        berApplet->log( strOK );
        berApplet->messageBox( strOK, this );
    }
    else
    {
        QString strErr = QString( "Verify fail: %1" ).arg(sMsg);
        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
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
        berApplet->warningBox( "You have to find trust certificate", this );
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
        berApplet->warningBox( "You have to find untrust certificate", this );
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
        berApplet->warningBox( "You have to find CRL", this );
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
        berApplet->warningBox( "You have to find target ceritifcate", this );
        return;
    }

    CRLInfoDlg crlInfoDlg;
    crlInfoDlg.setCRLPath( strPath );
    crlInfoDlg.exec();
}

void CertPVDDlg::clickTrustAdd()
{
    QString strPath = mTrustPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find trust certificate", this );
        return;
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( row );
    mPathTable->setRowHeight(row, 10 );
    mPathTable->setItem( row, 0, new QTableWidgetItem( tr("Trust")));
    mPathTable->setItem( row, 1, new QTableWidgetItem( strPath ));

    mTrustPathText->clear();
}

void CertPVDDlg::clickUntrustAdd()
{
    QString strPath = mUntrustPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find untrust certificate", this );
        return;
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( row );
    mPathTable->setRowHeight(row, 10 );
    mPathTable->setItem( row, 0, new QTableWidgetItem( tr("Untrust")));
    mPathTable->setItem( row, 1, new QTableWidgetItem( strPath ));

    mUntrustPathText->clear();
}

void CertPVDDlg::clickCRLAdd()
{
    QString strPath = mCRLPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( "You have to find CRL", this );
        return;
    }

    int row = mPathTable->rowCount();
    mPathTable->insertRow( row );
    mPathTable->setRowHeight(row, 10 );
    mPathTable->setItem( row, 0, new QTableWidgetItem( tr("CRL")));
    mPathTable->setItem( row, 1, new QTableWidgetItem( strPath ));

    mCRLPathText->clear();
}

void CertPVDDlg::clickListClear()
{
    int count = mPathTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        mPathTable->removeRow(0);
    }
}

void CertPVDDlg::clickPathClear()
{
    mTrustPathText->clear();
    mUntrustPathText->clear();
    mCRLPathText->clear();
    mTargetPathText->clear();
}

void CertPVDDlg::checkUseCheckTime()
{
    bool bVal = mUseCheckTimeCheck->isChecked();
    mVerifyDateTime->setEnabled(bVal);
}

void CertPVDDlg::clickParamAdd()
{
    QString strName = mParamCombo->currentText();
    QString strValue = mParamValueText->text();

    if( strValue.length() < 1 )
    {
        berApplet->warningBox( "You have to insert param value", this );
        return;
    }

    int row = mParamTable->rowCount();
    mParamTable->insertRow( row );
    mParamTable->setRowHeight(row, 10 );
    mParamTable->setItem( row, 0, new QTableWidgetItem( strName ));
    mParamTable->setItem( row, 1, new QTableWidgetItem( strValue ));

    mParamValueText->clear();
}

void CertPVDDlg::clickParamListClear()
{
    int count = mParamTable->rowCount();

    for( int i = 0; i < count; i++ )
    {
        mParamTable->removeRow(0);
    }
}