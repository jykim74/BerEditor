#include "mainwindow.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_tools.h"
#include "js_util.h"
#include "common.h"

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

    initUI();
    cert_path_ = "";
    memset( &cert_bin_, 0x00, sizeof(BIN));
    tabWidget->setCurrentIndex(0);
}

CertInfoDlg::~CertInfoDlg()
{
    JS_BIN_reset( &cert_bin_);
}

void CertInfoDlg::setCertPath(const QString strPath)
{
    cert_path_ = strPath;
}

void CertInfoDlg::setCertBIN( const BIN *pCert )
{
    cert_path_.clear();
    JS_BIN_reset( &cert_bin_ );
    JS_BIN_copy( &cert_bin_, pCert );
}

void CertInfoDlg::showEvent(QShowEvent *event)
{
    getFields();
}

void CertInfoDlg::getFields()
{
    int ret = 0;
    int i = 0;

    BIN binCert = {0,0};
    BIN binFinger = {0,0};
    BIN binPub = {0,0};

    JCertInfo  sCertInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    char    sNotBefore[64];
    char    sNotAfter[64];

    int nType = mFieldTypeCombo->currentIndex();

    if( cert_path_.length() < 1 && cert_bin_.nLen <= 0 )
    {
        berApplet->warningBox( tr( "Select certificate"), this );
        this->hide();
        return;
    }

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    clearTable();

    if( cert_bin_.nLen > 0 )
        JS_BIN_copy( &binCert, &cert_bin_ );
    else
        JS_BIN_fileReadBER( cert_path_.toLocal8Bit().toStdString().c_str(), &binCert );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr("fail to get certificate information"), this );
        JS_BIN_reset( &binCert );
        this->hide();
        return;
    }

    JS_PKI_genHash( "SHA1", &binCert, &binFinger );

    if( nType == FIELD_ALL || nType == FIELD_VERSION1_ONLY )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(sCertInfo.nVersion + 1)));
        i++;

        if( sCertInfo.pSerial )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSerial)));
            i++;
        }

        JS_UTIL_getDateTime( sCertInfo.uNotBefore, sNotBefore );
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotBefore")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBefore)));
        i++;

        JS_UTIL_getDateTime( sCertInfo.uNotAfter, sNotAfter );
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfter)));
        i++;

        if( sCertInfo.pSubjectName )
        {
            QString name = QString::fromUtf8( sCertInfo.pSubjectName );

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
            i++;
        }

        if( sCertInfo.pPublicKey )
        {
            int nKeyType = -1;
            int nOption = -1;

            QString strAlg;
            QString strParam;

            JS_BIN_decodeHex( sCertInfo.pPublicKey, &binPub );
            JS_PKI_getPubKeyInfo( &binPub, &nKeyType, &nOption );

            strAlg = JS_PKI_getKeyAlgName( nKeyType );

            if( nKeyType == JS_PKI_KEY_TYPE_ECC )
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

            item->setData( Qt::UserRole, QString( sCertInfo.pPublicKey ) );
            mFieldTable->setItem( i, 1, item );
            i++;
        }

        if( sCertInfo.pIssuerName )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("IssuerName")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pIssuerName)));
            i++;
        }

        if( sCertInfo.pSignAlgorithm )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignAlgorithm)));
            i++;
        }

        if( sCertInfo.pSignature )
        {
            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
            mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignature)));
            i++;
        }
    }

    if( nType == FIELD_ALL || nType == FIELD_EXTENSION_ONLY || nType == FIELD_CRITICAL_ONLY )
    {
        if( pExtInfoList )
        {
            JExtensionInfoList *pCurList = pExtInfoList;

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

    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binFinger );
    JS_BIN_reset( &binPub );

    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
}


void CertInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QStringList sFieldTypes = { tr("All"), tr("Version1 Only"), tr("Extension Only"), tr("Critical Extension Only"), tr("Attribute Only") };

    mFieldTypeCombo->addItems( sFieldTypes );

    mFieldTable->clear();
    mFieldTable->horizontalHeader()->setStretchLastSection(true);
    mFieldTable->setColumnCount(2);
    mFieldTable->setHorizontalHeaderLabels( sBaseLabels );
    mFieldTable->verticalHeader()->setVisible(false);
    mFieldTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mFieldTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeFieldType(int)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
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

void CertInfoDlg::changeFieldType( int index )
{
    getFields();
}
