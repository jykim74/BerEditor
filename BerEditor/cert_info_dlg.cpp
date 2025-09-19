/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "mainwindow.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_pvd.h"
#include "js_pki_tools.h"
#include "js_util.h"
#include "js_error.h"
#include "crl_info_dlg.h"
#include "settings_mgr.h"
#include "cert_man_dlg.h"
#include "common.h"
#include "ocsp_client_dlg.h"
#include "get_uri_dlg.h"

enum {
    FIELD_ALL = 0,
    FIELD_VERSION1_ONLY,
    FIELD_EXTENSION_ONLY,
    FIELD_CRITICAL_ONLY,
    FIELD_ATTRIBUTE_ONLY
};


QTableWidgetItem* CertInfoDlg::getExtNameItem( const QString strSN )
{
    QTableWidgetItem* item = NULL;

    if( strSN == JS_PKI_ExtNameAIA )
        item = new QTableWidgetItem( tr( "authorityInfoAccess" ));
    else if( strSN == JS_PKI_ExtNameAKI )
        item = new QTableWidgetItem( tr( "authorityKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameBC )
        item = new QTableWidgetItem( tr( "basicConstraints" ) );
    else if( strSN == JS_PKI_ExtNameCRLDP )
        item = new QTableWidgetItem( tr( "crlDistributionPoints" ) );
    else if( strSN == JS_PKI_ExtNameEKU )
        item = new QTableWidgetItem( tr( "extendedKeyUsage" ) );
    else if( strSN == JS_PKI_ExtNameIAN )
        item = new QTableWidgetItem( tr( "issuerAltName" ) );
    else if( strSN == JS_PKI_ExtNameKeyUsage )
        item = new QTableWidgetItem( tr( "keyUsage" ) );
    else if( strSN == JS_PKI_ExtNameNC )
        item = new QTableWidgetItem( tr( "nameConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePolicy )
        item = new QTableWidgetItem( tr( "certificatePolicies" ) );
    else if( strSN == JS_PKI_ExtNamePC )
        item = new QTableWidgetItem( tr( "policyConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePM )
        item = new QTableWidgetItem( tr( "policyMappings" ) );
    else if( strSN == JS_PKI_ExtNameSKI )
        item = new QTableWidgetItem( tr( "subjectKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameSAN )
        item = new QTableWidgetItem( tr( "subjectAltName" ) );
    else if( strSN == JS_PKI_ExtNameCRLNum )
        item = new QTableWidgetItem( tr( "crlNumber" ) );
    else if( strSN == JS_PKI_ExtNameIDP )
        item = new QTableWidgetItem( tr( "issuingDistributionPoint" ) );
    else if( strSN == JS_PKI_ExtNameCRLReason )
        item = new QTableWidgetItem( tr( "CRLReason" ) );
    else
        item = new QTableWidgetItem( strSN );


    return item;
}


CertInfoDlg::CertInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mSaveBtn, SIGNAL(clicked()), this, SLOT(clickSave()));
    connect( mSaveToManBtn, SIGNAL(clicked()), this, SLOT(clickSaveToMan()));
    connect( mSaveToCABtn, SIGNAL(clicked()), this, SLOT(clickSaveToCA()));
    connect( mSaveTrustedCABtn, SIGNAL(clicked()), SLOT(clickSaveTrustedCA()));

    connect( mMakeTreeBtn, SIGNAL(clicked()), this, SLOT(clickMakeTree()));
    connect( mGetCABtn, SIGNAL(clicked()), this, SLOT(clickGetCA()));
    connect( mGetCRLBtn, SIGNAL(clicked()), this, SLOT(clickGetCRL()));
    connect( mDecodeCertBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCert()));
    connect( mPathValidBtn, SIGNAL(clicked()), this, SLOT(clickPathValidation()));
    connect( mVerifyCertBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCert()));
    connect( mOCSPCheckBtn, SIGNAL(clicked()), this, SLOT(clickOCSPCheck()));
    connect( mCRLCheckBtn, SIGNAL(clicked()), this, SLOT(clickCRLCheck()));

    connect( mOCSPClientBtn, SIGNAL(clicked()), this, SLOT(clickOCSPClient()));
    connect( mGetCA_BERBtn, SIGNAL(clicked()), this, SLOT(clickGetCA_BER()));
    connect( mGetCRL_BERBtn, SIGNAL(clicked()), this, SLOT(clickGetCRL_BER()));

    connect( mCertTree, SIGNAL(itemClicked(QTreeWidgetItem*,int)), this, SLOT(clickTreeItem(QTreeWidgetItem*,int)));

    initUI();

    cert_path_.clear();
    memset( &cert_bin_, 0x00, sizeof(BIN));
    memset( &cert_info_, 0x00, sizeof(cert_info_));
    ext_info_list_ = NULL;
    self_sign_ = 0;
    path_list_ = NULL;

    tabWidget->setCurrentIndex(0);
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mInfoTab->layout()->setSpacing(5);
    mInfoTab->layout()->setMargin(5);
    mPathTab->layout()->setSpacing(5);
    mPathTab->layout()->setMargin(5);

    mManGroup->layout()->setSpacing(5);
    mManGroup->layout()->setMargin(5);
#endif


    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CertInfoDlg::~CertInfoDlg()
{
    resetData();
}

void CertInfoDlg::setTitle( const QString strName )
{
    QString strTitle = tr("Certificate");

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

    setWindowTitle( strTitle );
}


int CertInfoDlg::setCertPath(const QString strPath)
{
    int ret = 0;
    resetData();

    cert_path_ = strPath;
    setTitle( strPath );

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &cert_bin_ );

    return ret;
}

void CertInfoDlg::setCertBIN( const BIN *pCert, const QString strTitle )
{
    resetData();
    JS_BIN_copy( &cert_bin_, pCert );
    setTitle( strTitle );
}

void CertInfoDlg::showEvent(QShowEvent *event)
{
    getFields();
    bool bCA = false;

    mCertTree->clear();
    QTreeWidgetItem *item = new QTreeWidgetItem;

    item->setText( 0, cert_info_.pSubjectName );
    item->setIcon(0, QIcon(":/images/cert.png"));
    mCertTree->insertTopLevelItem(0, item);

    QString strAIA = getValueFromExtList( kExtNameAIA );
    QString strCRLDP = getValueFromExtList( kExtNameCRLDP );
    QString strBC = getValueFromExtList( kExtNameBC );

    QString strOCSP = getOCSP_URIFromExt( strAIA );
    QString strCA = getCA_URIFromExt( strAIA );
    QString strCRL = getCRL_URIFromExt( strCRLDP );

    bCA = isCA( strBC );

    if( strCA.length() < 4 )
    {
        mGetCABtn->setEnabled( false );
        mOCSPCheckBtn->setEnabled( false );
        mPathValidBtn->setEnabled( false );
        mMakeTreeBtn->setEnabled( false );
        mVerifyCertBtn->setEnabled( false );
        mGetCA_BERBtn->setEnabled( false );

        mGetCABtn->setToolTip( tr( "There is no CA url" ));
        mOCSPCheckBtn->setToolTip( tr( "There is no CA url" ));
        mPathValidBtn->setToolTip( tr( "There is no CA url" ));
        mMakeTreeBtn->setToolTip( tr( "There is no CA url" ));
        mVerifyCertBtn->setToolTip( tr( "There is no CA url" ));
        mGetCA_BERBtn->setToolTip( tr( "There is no CA url" ));
    }

    if( strCRL.length() < 4 )
    {
        mGetCRLBtn->setEnabled( false );
        mCRLCheckBtn->setEnabled( false );
        mGetCRL_BERBtn->setEnabled( false );

        mGetCRLBtn->setToolTip( tr( "There is no CRL url" ) );
        mCRLCheckBtn->setToolTip( tr( "There is no CRL url" ) );
        mGetCRL_BERBtn->setToolTip( tr( "There is no CRL url" ));
    }

    if( strOCSP.length() < 4 )
    {
        mOCSPCheckBtn->setEnabled( false );
        mOCSPCheckBtn->setToolTip( tr( "There is no OCSP url" ) );
        mOCSPClientBtn->setEnabled( false );
        mOCSPClientBtn->setToolTip( tr( "There is no OCSP url" ) );
    }

    if( berApplet->isLicense() == true )
    {
        if( bCA == false )
            mSaveToCABtn->hide();
        else
            mSaveToCABtn->show();

        if( self_sign_ == false )
            mSaveTrustedCABtn->hide();
        else
            mSaveTrustedCABtn->show();
    }
}

void CertInfoDlg::getFields()
{
    int ret = 0;
    int i = 0;

    BIN binFinger = {0,0};
    BIN binPub = {0,0};

    char    sNotBefore[64];
    char    sNotAfter[64];

    int nType = mFieldTypeCombo->currentIndex();

    if( cert_bin_.nLen <= 0 )
    {
        berApplet->warningBox( tr( "Select a certificate"), this );
        close();
        return;
    }

    clearTable();

    ret = JS_PKI_getCertInfo2( &cert_bin_, &cert_info_, &ext_info_list_, &self_sign_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to get certificate information"), this );
        this->hide();
        return;
    }

    if( self_sign_ == true ) mGetCABtn->setEnabled( false );

    JS_PKI_genHash( "SHA1", &cert_bin_, &binFinger );

    if( nType == FIELD_ALL || nType == FIELD_VERSION1_ONLY )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(cert_info_.nVersion + 1)));
        i++;

        if( cert_info_.pSerial )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(cert_info_.pSerial)));
            i++;
        }

        JS_UTIL_getDateTime( cert_info_.tNotBefore, sNotBefore );
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotBefore")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBefore)));
        i++;

        JS_UTIL_getDateTime( cert_info_.tNotAfter, sNotAfter );
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfter)));
        i++;

        if( cert_info_.pSubjectName )
        {
            QString name = QString::fromUtf8( cert_info_.pSubjectName );

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
            i++;
        }

        if( cert_info_.pPublicKey )
        {
            int nKeyType = -1;
            int nOption = -1;

            QString strAlg;
            QString strParam;

            JS_BIN_decodeHex( cert_info_.pPublicKey, &binPub );
            JS_PKI_getPubKeyInfo( &binPub, &nKeyType, &nOption );

            strAlg = JS_PKI_getKeyAlgName( nKeyType );

            if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
            {
                strParam = JS_PKI_getSNFromNid( nOption );
            }
            else if( nKeyType == JS_PKI_KEY_TYPE_RSA || nKeyType == JS_PKI_KEY_TYPE_DSA )
            {
                strParam = QString( "%1" ).arg( nOption );
            }

            QTableWidgetItem *item = NULL;

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));

            if( strParam.length() > 0 )
                item = new QTableWidgetItem(QString("%1 (%2)").arg( strAlg ).arg( strParam ));
            else
                item = new QTableWidgetItem(QString("%1").arg(strAlg));

            item->setData( Qt::UserRole, QString( cert_info_.pPublicKey ) );
            mFieldTable->setItem( i, 1, item );
            i++;
        }

        if( cert_info_.pIssuerName )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("IssuerName")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(cert_info_.pIssuerName)));
            i++;
        }

        if( cert_info_.pSignAlgorithm )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(cert_info_.pSignAlgorithm)));
            i++;
        }

        if( cert_info_.pSignature )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(cert_info_.pSignature)));
            i++;
        }
    }

    if( nType == FIELD_ALL || nType == FIELD_EXTENSION_ONLY || nType == FIELD_CRITICAL_ONLY )
    {
        if( ext_info_list_ )
        {
            JExtensionInfoList *pCurList = ext_info_list_;

            while( pCurList )
            {
                QString strValue;
                QString strSN = pCurList->sExtensionInfo.pOID;
                bool bCrit = pCurList->sExtensionInfo.bCritical;
                getInfoValue( &pCurList->sExtensionInfo, strValue );

                pCurList = pCurList->pNext;

                if( bCrit == false && nType == FIELD_CRITICAL_ONLY ) continue;

                QTableWidgetItem *item = new QTableWidgetItem( strValue );
                if( bCrit )
                    item->setIcon(QIcon(":/images/critical.png"));
                else
                    item->setIcon(QIcon(":/images/normal.png"));

                mFieldTable->insertRow(i);
                mFieldTable->setRowHeight(i,10);
                mFieldTable->setItem(i,0, getExtNameItem(strSN));
                mFieldTable->setItem(i, 1, item );

                i++;
            }
        }
    }

    if( nType == FIELD_ALL || nType == FIELD_ATTRIBUTE_ONLY )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFinger.pVal, binFinger.nLen))));
        i++;
    }

    JS_BIN_reset( &binFinger );
    JS_BIN_reset( &binPub );
}


void CertInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QStringList sFieldTypes = { tr("All"), tr("Version1 Only"), tr("Extension Only"), tr("Critical Extension Only"), tr("Attribute Only") };

    mFieldTypeCombo->addItems( sFieldTypes );

    mFieldTable->clear();
    mFieldTable->horizontalHeader()->setStretchLastSection(true);
    mFieldTable->setColumnCount(sBaseLabels.size());
    mFieldTable->setHorizontalHeaderLabels( sBaseLabels );
    mFieldTable->verticalHeader()->setVisible(false);
    mFieldTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mFieldTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mFieldTable->setColumnWidth( 0, 160 );

    connect( mFieldTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeFieldType(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));

    if( berApplet->isLicense() == false )
    {
        tabWidget->setTabEnabled( 1, false );
        mSaveToManBtn->hide();
        mSaveToCABtn->hide();
        mSaveTrustedCABtn->hide();
    }
    else
    {
        mCertTree->clear();
        mCertTree->header()->setVisible( false );
        mCertTree->setColumnCount(1);
    }
}

void CertInfoDlg::clickField(QModelIndex index)
{
    int row = index.row();
    QTableWidgetItem *item0 = mFieldTable->item( row, 0 );
    QTableWidgetItem* item1 = mFieldTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    if( item0->text() == tr( "PublicKey" ) )
    {
        QString strPub = item1->data(Qt::UserRole).toString();
        mDetailText->setPlainText( strPub );
    }
    else
    {
        mDetailText->setPlainText( item1->text() );
    }
}


void CertInfoDlg::clearTable()
{
    int rowCnt = mFieldTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mFieldTable->removeRow(0);
}

void CertInfoDlg::resetData()
{
    JS_BIN_reset( &cert_bin_);
    JS_PKI_resetCertInfo( &cert_info_ );
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( path_list_ ) JS_BIN_resetList( &path_list_ );
}

int CertInfoDlg::saveAsPEM( const BIN *pData )
{
    if( pData == NULL || pData->nLen <= 0 ) return -1;

    QString strPath;
    QString fileName = berApplet->findSaveFile( this, JS_FILE_TYPE_CERT, strPath );

    if( fileName.length() > 0 )
    {
        int ret = JS_BIN_writePEM( pData, JS_PEM_TYPE_CERTIFICATE, fileName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Save a certificate or CRL as a PEM file" ), this );
        }
    }

    return 0;
}

void CertInfoDlg::changeFieldType( int index )
{
    getFields();
}

void CertInfoDlg::clickSave()
{   
    saveAsPEM( &cert_bin_ );
}

void CertInfoDlg::clickSaveToMan()
{
    int ret = 0;
    QString strPath = berApplet->settingsMgr()->otherCertPath();

    ret = CertManDlg::writeNameHash( strPath, &cert_bin_ );

    if( ret > 0 )
        berApplet->messageLog( tr( "The certificate is saved to manager folder" ), this );
    else
        berApplet->warnLog( tr( "failed to save to manager foler: %1" ).arg( ret ), this );
}

void CertInfoDlg::clickSaveToCA()
{
    int ret = 0;
    QString strCAPath = berApplet->settingsMgr()->CACertPath();

    ret = CertManDlg::writeNameHash( strCAPath, &cert_bin_ );

    if( ret > 0 )
        berApplet->messageLog( tr( "The certificate is saved to manager folder" ), this );
    else
        berApplet->warnLog( tr( "failed to save to manager foler: %1" ).arg( ret ), this );
}

void CertInfoDlg::clickSaveTrustedCA()
{
    int ret = 0;
    unsigned long uHash = 0;

    QString strTrustedCAPath = berApplet->settingsMgr()->trustCertPath();

    if( QDir( strTrustedCAPath ).exists() == false )
        QDir().mkdir( strTrustedCAPath );

    JS_PKI_getSubjectNameHash( &cert_bin_, &uHash );
    berApplet->log( QString( "Subject Hash: %1").arg( uHash, 8, 16, QLatin1Char( '0') ));
    QString strFileName = QString( "%1/%2.0" ).arg( strTrustedCAPath ).arg( uHash, 8, 16, QLatin1Char('0'));

    if( QFileInfo::exists( strFileName ) == true )
    {
        berApplet->warningBox( tr( "The file(%1) is already existed").arg( strFileName ), this );
        return;
    }

    ret = CertManDlg::writeNameHash( strTrustedCAPath, &cert_bin_ );
    if( ret > 0 )
        berApplet->messageBox( tr( "The Certificate saved to trusted CA directory"), this );
    else
        berApplet->warningBox( tr( "The Certificate failed to save to trusted CA directory [%1]" ).arg(ret), this );
}

void CertInfoDlg::clickMakeTree()
{
    int ret = 0;
    BIN binCert = {0,0};
    BIN binCA = {0,0};
    char sMsg[1024];

    JCertInfo sCertInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    QTreeWidgetItem* child = NULL;
    QString strExtValue;
    QString strCAPath = berApplet->settingsMgr()->CACertPath();

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    mCertTree->clear();
    if( path_list_ ) JS_BIN_resetList( &path_list_ );

    JS_BIN_copy( &binCert, &cert_bin_ );


    while( 1 )
    {
        int bSelfSign = 0;
        ret = JS_PKI_getCertInfo2( &binCert, &sCertInfo, &pExtInfoList, &bSelfSign );
        if( ret != 0 ) break;

        QTreeWidgetItem* item = new QTreeWidgetItem;
        item->setText( 0, sCertInfo.pSubjectName );

        if( bSelfSign == true )
            item->setIcon( 0, QIcon( ":/images/root_cert.png" ));
        else
            item->setIcon( 0, QIcon( ":/images/cert.png" ));

        JS_BIN_addList( &path_list_, &binCert );
        item->addChild( child );
        child = item;

        if( bSelfSign == 1 ) break;

        ret = CertManDlg::readCA(  strCAPath, &binCert, &binCA );
        if( ret != CKR_OK )
        {
            strExtValue = getValueFromExtList( kExtNameAIA, pExtInfoList );
            if( strExtValue.length() > 0 )
            {
                ret = getCA( strExtValue, &binCA );
                if( ret != 0 ) break;

                ret = JS_PKI_CertVerifyByCA( &binCA, NULL, &binCert, sMsg );
                if( ret != JSR_VERIFY ) break;
            }
        }
        else
        {
            ret = JS_PKI_CertVerifyByCA( &binCA, NULL, &binCert, sMsg );
            if( ret != JSR_VERIFY )
            {
                JS_BIN_reset( &binCA );

                strExtValue = getValueFromExtList( kExtNameAIA, pExtInfoList );
                if( strExtValue.length() > 0 )
                {
                    ret = getCA( strExtValue, &binCA );
                    if( ret != 0 ) break;
                }

                ret = JS_PKI_CertVerifyByCA( &binCA, NULL, &binCert, sMsg );
                if( ret != JSR_VERIFY ) break;
            }
        }

        JS_BIN_reset( &binCert );
        JS_BIN_copy( &binCert, &binCA );
        JS_BIN_reset( &binCA );

        JS_PKI_resetCertInfo( &sCertInfo );
        if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    }

    mCertTree->insertTopLevelItem( 0, child );

    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );

    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    mCertTree->expandAll();
}

void CertInfoDlg::clickGetCA()
{
    int ret = 0;
    BIN binCA = {0,0};
    QString strExtValue = getValueFromExtList( kExtNameAIA );

    ret = getCA( strExtValue, &binCA );

    if( ret == 0 )
    {
    //    saveAsPEM( &binCA );
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &binCA );
        certInfo.exec();
    }
    else
        berApplet->elog( QString("failed to get CA certificate [%1]").arg(ret));

    JS_BIN_reset( &binCA );
}

void CertInfoDlg::clickGetCRL()
{
    int ret = 0;
    BIN binCRL = {0,0};
    QString strExtValue = getValueFromExtList( kExtNameCRLDP );

    ret = getCRL( strExtValue, &binCRL );

    if( ret == 0 )
    {
    //    saveAsPEM( &binCRL );
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &binCRL );
        crlInfo.exec();
    }
    else
        berApplet->elog( QString("failed to get CRL [%1]").arg(ret));

    JS_BIN_reset( &binCRL );
}

void CertInfoDlg::clickDecodeCert()
{
    berApplet->decodeData( &cert_bin_, cert_path_ );
}

void CertInfoDlg::clickPathValidation()
{
    int ret = 0;
    BINList *pTrustList = NULL;
    BINList *pUntrustList = NULL;
    BINList *pCRLList = NULL;
    const BINList *pAtList = NULL;

    char sResMsg[128];
    int nPathCount = 0;

    if( path_list_ == NULL ) clickMakeTree();

    nPathCount = JS_BIN_countList( path_list_ );

    for( int i = 0; i < nPathCount; i++ )
    {
        pAtList = JS_BIN_getListAt( i, path_list_ );

        if( i == (nPathCount - 1) )
            JS_BIN_addList( &pTrustList, &pAtList->Bin );
        else
            JS_BIN_addList( &pUntrustList, &pAtList->Bin );
    }

    ret = JS_PKI_CertPVD( pTrustList, pUntrustList, pCRLList, NULL, &cert_bin_, sResMsg );

    berApplet->messageBox( tr( "Path verification result : %1 (%2)").arg( sResMsg ).arg( ret ), this );

    if( pTrustList ) JS_BIN_resetList( &pTrustList );
    if( pUntrustList ) JS_BIN_resetList( &pUntrustList );
    if( pCRLList ) JS_BIN_resetList( &pCRLList );

    mCertTree->expandAll();
}

void CertInfoDlg::clickVerifyCert()
{
    int ret = 0;
    BIN binCA = {0,0};
    BIN binCRL = {0,0};

    char sMsg[1024];

    QString strExtAIA = getValueFromExtList( kExtNameAIA );
    QString strExtCRLDP = getValueFromExtList( kExtNameCRLDP );

    memset( sMsg, 0x00, sizeof(sMsg));

    ret = getCA( strExtAIA, &binCA );
    if( ret != 0 ) berApplet->elog( tr( "failed to get CA certificate [%1]").arg( ret ));

    ret = getCRL( strExtCRLDP, &binCRL );
    if( ret != 0 ) berApplet->elog( tr( "failed to get CRL [%1]").arg( ret ));

    ret = JS_PKI_CertVerifyByCA( &binCA, &binCRL, &cert_bin_, sMsg );

    berApplet->messageBox( tr( "Verification results: %1(%2)").arg( sMsg ).arg( ret ), this );

end :
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCRL );
}

void CertInfoDlg::clickOCSPCheck()
{
    int ret = 0;

    QString strURI;
    BIN binCA = {0,0};
    JCertStatusInfo sStatusInfo;

    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    QString strExtValue = getValueFromExtList( kExtNameAIA );
    berApplet->log( QString( "AIA : %1" ).arg( strExtValue ));

    ret = getCA( strExtValue, &binCA );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to get CA certificate: %1").arg( ret ), this);
        return;
    }

    strURI = getOCSP_URIFromExt( strExtValue );

    if( strURI.length() < 1 )
    {
        berApplet->warningBox( tr( "failed to get OCSP URI address" ), this );
        return;
    }

    berApplet->log( QString( "OCSP URI: %1").arg( strURI));
    ret = checkOCSP( strURI, &binCA, &cert_bin_, &sStatusInfo );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Certificate status verification failed with OCSP: %1(%2)")
                                  .arg( JS_OCSP_getResponseStatusName(ret) )
                                  .arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr( "Verification results with OCSP: %1(%2)" )
                                  .arg( JS_OCSP_getCertStatusName( sStatusInfo.nStatus ) )
                                  .arg( sStatusInfo.nStatus ), this);
    }

    JS_BIN_reset( &binCA );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
}

void CertInfoDlg::clickCRLCheck()
{
    int ret = 0;
    BIN binCRL = {0,0};
    QString strExtValue = getValueFromExtList( kExtNameCRLDP );

    ret = getCRL( strExtValue, &binCRL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to get CRL : %1").arg( ret ), this );
    }
    else
    {
        int nStatus = -1;
        time_t tRevokedTime = 0;
        char sSerial[32];
        char sRevokedTime[64];

        memset( sSerial, 0x00, sizeof(sSerial));
        memset( sRevokedTime, 0x00, sizeof(sRevokedTime));

        ret = JS_PKI_getStatusFromCRL( &binCRL, &cert_bin_, &nStatus, &tRevokedTime, sSerial );
        if( ret != 0 )
        {
            berApplet->elog( QString("failed to get certificate status from CRL: %1" ).arg( ret ) );
        }
        else
        {
            JS_UTIL_getDateTime( tRevokedTime, sRevokedTime );

            if( nStatus == 0 )
                berApplet->messageBox( tr( "The certificate is not revoked (STATUS:Good)" ), this );
            else
                berApplet->warningBox( tr( "The certificate is revoked: (STATUS:Revoked %1:%2)" )
                                          .arg(nStatus).arg( sSerial ).arg( sRevokedTime ), this );
        }
    }

    JS_BIN_reset( &binCRL );
}

void CertInfoDlg::clickTreeItem(QTreeWidgetItem* item, int index)
{
    QString strText = QString( "DN: %2\n").arg( item->text(0));

    mCertLogText->setPlainText( strText );
}

void CertInfoDlg::clickOCSPClient()
{
    QString strAIA = getValueFromExtList( kExtNameAIA );

    QString strOCSP = getOCSP_URIFromExt( strAIA );
    QString strCA = getCA_URIFromExt( strAIA );

    OCSPClientDlg ocspClient;
    ocspClient.setURI( strOCSP );
    ocspClient.setCA( strCA );
    ocspClient.setCert( cert_info_.pSubjectName, &cert_bin_ );
    ocspClient.exec();
}

void CertInfoDlg::clickGetCA_BER()
{
    QString strAIA = getValueFromExtList( kExtNameAIA );
    QString strCA = getCA_URIFromExt( strAIA );


    GetURIDlg getURI;
    getURI.setCA( strCA );
    getURI.exec();
}

void CertInfoDlg::clickGetCRL_BER()
{
    QString strCRLDP = getValueFromExtList( kExtNameCRLDP );
    QString strCRL = getCRL_URIFromExt( strCRLDP );

    GetURIDlg getURI;
    getURI.setCRL( strCRL );
    getURI.exec();
}

const QString CertInfoDlg::getValueFromExtList( const QString strExtName )
{
    QString strValue;

    JExtensionInfoList *pCurList = NULL;

    pCurList = ext_info_list_;

    while( pCurList )
    {
        QString strSN;

        strSN = pCurList->sExtensionInfo.pOID;

        if( strSN == strExtName )
        {
            strValue = pCurList->sExtensionInfo.pValue;
            break;
        }

        pCurList = pCurList->pNext;
    }

    return strValue;
}

const QString CertInfoDlg::getCRL_URIFromExt( const QString strExtCRLDP )
{
    QString strURI;
    QString strCRLDP;

    strCRLDP = getExtValue( kExtNameCRLDP, strExtCRLDP, false );

    QStringList infoList = strCRLDP.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );
        if( partList.size() < 2 ) continue;

        if( partList.at(0) == "URI" )
        {
            strURI = partList.at(1);
            break;
        }
    }

    return strURI;
}

const QString CertInfoDlg::getOCSP_URIFromExt( const QString strExtAIA )
{
    QString strAIA;
    QString strURI;

    strAIA = getExtValue( kExtNameAIA, strExtAIA, false );

    QStringList infoList = strAIA.split( "%%" );
    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split("#");

        if( partList.size() < 3 ) continue;

        QString strMethod = partList.at(0);
        QString strType = partList.at(1);
        QString strName = partList.at(2);

        QStringList methodVal = strMethod.split( "$" );
        QStringList typeVal = strType.split( "$" );
        QStringList nameVal = strName.split( "$" );

        if( methodVal.size() < 2 || typeVal.size() < 2 || nameVal.size() < 2 ) continue;

        if( methodVal.at(1).toUpper() == "OCSP" )
        {
            if( typeVal.at(1) == "URI")
            {
                strURI = nameVal.at(1);
                break;
            }
        }
    }

    return strURI;
}

const QString CertInfoDlg::getCA_URIFromExt( const QString strExtAIA )
{
    QString strAIA;
    QString strURI;

    strAIA = getExtValue( kExtNameAIA, strExtAIA, false );

    QStringList infoList = strAIA.split( "%%" );
    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split("#");

        if( partList.size() < 3 ) continue;

        QString strMethod = partList.at(0);
        QString strType = partList.at(1);
        QString strName = partList.at(2);

        QStringList methodVal = strMethod.split( "$" );
        QStringList typeVal = strType.split( "$" );
        QStringList nameVal = strName.split( "$" );

        if( methodVal.size() < 2 || typeVal.size() < 2 || nameVal.size() < 2 ) continue;

        if( methodVal.at(1).toUpper() == "CA ISSUERS" )
        {
            if( typeVal.at(1) == "URI")
            {
                strURI = nameVal.at(1);
                break;
            }
        }
    }

    return strURI;
}

bool CertInfoDlg::isCA( const QString strExtBC )
{
    QString strBC;

    if( strExtBC.length() < 1 )
        return false;

    strBC = getExtValue( kExtNameBC, strExtBC, false );

    if( strBC.contains( "CA" ) == true )
        return true;

    return false;
}

int CertInfoDlg::getCA( const QString strExtAIA, BIN *pCA )
{
    int ret = 0;
    QString strURI;

//    berApplet->log( QString( "AIA : %1" ).arg( strExtAIA ));
    strURI = getCA_URIFromExt( strExtAIA );

    if( strURI.length() < 1 )
    {
        berApplet->elog( "failed to get CA certificate URI address" );
        return JSR_SSL_NO_CA_ISSUER_INFO;
    }

    berApplet->log( QString( "CA URI: %1").arg( strURI));
    ret = getDataFromURI( strURI, pCA );

    return ret;
}

int CertInfoDlg::getCRL( const QString strExtCRLDP, BIN *pCRL )
{
    int ret = 0;
    QString strURI;

    berApplet->log( QString( "CRLDP : %1" ).arg( strExtCRLDP ));
    strURI = getCRL_URIFromExt( strExtCRLDP );

    if( strURI.length() < 1 )
    {
        berApplet->elog( "failed to get CRL URI address" );
        return JSR_SSL_NO_CRLDP_INFO;
    }

    berApplet->log( QString( "CRL URI: %1").arg( strURI));
    ret = getDataFromURI( strURI, pCRL );

    return ret;
}

const QString CertInfoDlg::getValueFromExtList( const QString strExtName, JExtensionInfoList *pExtList )
{
    QString strValue;

    JExtensionInfoList *pCurList = NULL;

    pCurList = pExtList;

    while( pCurList )
    {
        QString strSN;

        strSN = pCurList->sExtensionInfo.pOID;

        if( strSN == strExtName )
        {
            strValue = pCurList->sExtensionInfo.pValue;
            break;
        }

        pCurList = pCurList->pNext;
    }

    return strValue;
}
