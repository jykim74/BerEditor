/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "csr_info_dlg.h"
#include "common.h"
#include "ber_applet.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_tools.h"

CSRInfoDlg::CSRInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    req_path_.clear();
    memset( &req_bin_, 0x00, sizeof(BIN));
    memset( &req_info_, 0x00, sizeof(req_info_));
    ext_info_list_ = NULL;

    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mSaveBtn, SIGNAL(clicked()), this, SLOT(clickSave()));
    connect( mVerifyCSRBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCSR()));
    connect( mDecodeCSRBtn, SIGNAL(clicked()), this, SLOT(clickDecodeCSR()));

    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CSRInfoDlg::~CSRInfoDlg()
{
    resetData();
}

void CSRInfoDlg::resetData()
{
    JS_BIN_reset( &req_bin_);
    JS_PKI_resetReqInfo( &req_info_ );
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
}

int CSRInfoDlg::setReqPath( const QString strPath )
{
    int ret = 0;
    resetData();

    ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &req_bin_ );
    setTitle( strPath );
    req_path_ = strPath;

    return ret;
}

void CSRInfoDlg::setReqBIN( const BIN *pReq, const QString strTitle )
{
    JS_BIN_copy( &req_bin_, pReq );
    setTitle( strTitle );
}

void CSRInfoDlg::showEvent(QShowEvent *event)
{
    initUI();
    initialize();
}

void CSRInfoDlg::setTitle( const QString strName )
{
    QString strTitle = tr("CSR");

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

    setWindowTitle( strTitle );
}


void CSRInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mFieldTable->clear();
    mFieldTable->horizontalHeader()->setStretchLastSection(true);
    mFieldTable->setColumnCount(2);
    mFieldTable->setHorizontalHeaderLabels( sBaseLabels );
    mFieldTable->verticalHeader()->setVisible(false);
    mFieldTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mFieldTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mFieldTable->setColumnWidth( 0, 140 );
}

int CSRInfoDlg::saveAsPEM( const BIN *pData )
{
    if( pData == NULL || pData->nLen <= 0 ) return -1;


    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath;

    QString strFilter = tr("CSR Files (*.csr);;PEM Files (*.pem);;All Files (*.*)");
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( this,
                                                    tr("Export Files"),
                                                    strPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 )
    {
        int ret = JS_BIN_writePEM( pData, JS_PEM_TYPE_CSR, fileName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "The CSR was saved in PEM format." ), this );
        }
    }

    return 0;
}

void CSRInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binPub = {0,0};

    if( berApplet->isLicense() == false ) mValidGroup->setEnabled( false );

    if( req_bin_.nLen < 0 )
    {
        berApplet->warningBox( tr( "Select a CSR"), this );
        this->hide();
        return;
    }

    ret = JS_PKI_getReqInfo( &req_bin_, &req_info_, 1, &ext_info_list_ );

    if( ret != 0 )
    {
        berApplet->warningBox( tr("failed to get CSR information"), this );
        goto end;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(req_info_.nVersion + 1)));
    i++;

    if( req_info_.pSubjectDN )
    {
        QString name = QString::fromUtf8( req_info_.pSubjectDN );

        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Verify")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(req_info_.bVerify ? "Verify" : "Not Verify")));
    i++;

    if( req_info_.pPublicKey )
    {
        int nKeyType = -1;
        int nOption = -1;

        QString strAlg;
        QString strParam;

        JS_BIN_decodeHex( req_info_.pPublicKey, &binPub );
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

        item->setData( Qt::UserRole, QString( req_info_.pPublicKey ) );
        mFieldTable->setItem( i, 1, item );
        i++;
    }

    if( req_info_.pSignAlgorithm )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(req_info_.pSignAlgorithm)));
        i++;
    }

    if( req_info_.pSignature )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(req_info_.pSignature)));
        i++;
    }

    if( req_info_.pChallenge )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Challenge")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(req_info_.pChallenge)));
        i++;
    }

    if( req_info_.pUnstructuredName )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("UnstructuredName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(req_info_.pUnstructuredName)));
        i++;
    }


    if( ext_info_list_ )
    {
        JExtensionInfoList *pCurList = ext_info_list_;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);

            mFieldTable->setItem(i,0, getExtNameItem( strSN ));
            mFieldTable->setItem(i, 1, item );


            pCurList = pCurList->pNext;
            i++;
        }
    }

end :
    JS_BIN_reset( &binPub );
}

QTableWidgetItem* CSRInfoDlg::getExtNameItem( const QString strSN )
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

void CSRInfoDlg::clickField(QModelIndex index)
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

void CSRInfoDlg::clickSave()
{
    saveAsPEM( &req_bin_ );
}

void CSRInfoDlg::clickVerifyCSR()
{
    int ret = JS_PKI_verifyCSR( &req_bin_ );

    if( ret == 1 )
        berApplet->messageBox( tr( "CSR verification successful" ), this );
    else
        berApplet->messageBox( tr( "CSR verification failed [%1]" ).arg(ret), this );
}

void CSRInfoDlg::clickDecodeCSR()
{
    berApplet->decodeData( &req_bin_, req_path_ );
}
