#include "x509_compare_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "csr_info_dlg.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_pvd.h"
#include "js_pki_tools.h"
#include "js_util.h"

X509CompareDlg::X509CompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    memset( &A_bin_, 0x00, sizeof(BIN));
    memset( &B_bin_, 0x00, sizeof(BIN));

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAFindBtn, SIGNAL(clicked()), this, SLOT(clickAFind()));
    connect( mBFindBtn, SIGNAL(clicked()), this, SLOT(clickBFind()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mCompareBtn, SIGNAL(clicked()), this, SLOT(clickCompare()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

X509CompareDlg::~X509CompareDlg()
{
    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );
}

void X509CompareDlg::initUI()
{
    QStringList sTypeList = { tr("Certificate" ), tr( "CRL" ), tr( "CSR" ) };
    QStringList sBaseLabels = { tr("Field"), tr("A Value"), tr( "B Value" ), tr( "O|X") };

    mCompareTable->clear();
    mCompareTable->horizontalHeader()->setStretchLastSection(true);
    mCompareTable->setColumnCount(sBaseLabels.size());
    mCompareTable->setHorizontalHeaderLabels( sBaseLabels );
    mCompareTable->verticalHeader()->setVisible(false);
    mCompareTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCompareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCompareTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mTypeCombo->addItems( sTypeList );
}


void X509CompareDlg::initialize()
{

}

void X509CompareDlg::clickAFind()
{
    QString strPath = mAPathText->text();

    QString strFilePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFilePath.length() > 0 )
    {
        mAPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickBFind()
{
    QString strPath = mBPathText->text();

    QString strFilePath = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFilePath.length() > 0 )
    {
        mBPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickClear()
{
    mCompareTable->setRowCount(0);
}

int X509CompareDlg::compareCert()
{
    int i = 0;
    int ret = 0;

    JCertInfo ACertInfo;
    JCertInfo BCertInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    BIN binFinger = {0,0};
    BIN binPub = {0,0};

    char    sNotBefore[64];
    char    sNotAfter[64];

    memset( &ACertInfo, 0x00, sizeof(JCertInfo));
    memset( &BCertInfo, 0x00, sizeof(JCertInfo));

    ret = JS_PKI_getCertInfo( &A_bin_, &ACertInfo, &pAExtList );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_PKI_getCertInfo( &B_bin_, &BCertInfo, &pBExtList );
    if( ret != 0 )
    {
        goto end;
    }

    JS_PKI_genHash( "SHA1", &A_bin_, &binFinger );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(ACertInfo.nVersion + 1)));
    i++;

    if( ACertInfo.pSerial )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSerial)));
        i++;
    }

    JS_UTIL_getDateTime( ACertInfo.uNotBefore, sNotBefore );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NotBefore")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBefore)));
    i++;

    JS_UTIL_getDateTime( ACertInfo.uNotAfter, sNotAfter );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfter)));
    i++;

    if( ACertInfo.pSubjectName )
    {
        QString name = QString::fromUtf8( ACertInfo.pSubjectName );

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    if( ACertInfo.pPublicKey )
    {
        int nKeyType = -1;
        int nOption = -1;

        QString strAlg;
        QString strParam;

        JS_BIN_decodeHex( ACertInfo.pPublicKey, &binPub );
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

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));

        if( strParam.length() > 0 )
            item = new QTableWidgetItem(QString("%1 (%2)").arg( strAlg ).arg( strParam ));
        else
            item = new QTableWidgetItem(QString("%1").arg(strAlg));

        item->setData( Qt::UserRole, QString( ACertInfo.pPublicKey ) );
        mCompareTable->setItem( i, 1, item );
        i++;
    }

    if( ACertInfo.pIssuerName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("IssuerName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pIssuerName)));
        i++;
    }

    if( ACertInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSignAlgorithm)));
        i++;
    }

    if( ACertInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSignature)));
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFinger.pVal, binFinger.nLen))));
    i++;

    if( pAExtList )
    {
        JExtensionInfoList *pCurList = pAExtList;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            pCurList = pCurList->pNext;


            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mCompareTable->insertRow(i);
            mCompareTable->setRowHeight(i,10);
            mCompareTable->setItem(i,0, CertInfoDlg::getExtNameItem(strSN));
            mCompareTable->setItem(i, 1, item );

            i++;
        }
    }

end :
    JS_PKI_resetCertInfo( &ACertInfo );
    JS_PKI_resetCertInfo( &BCertInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binFinger );
    JS_BIN_reset( &binPub );
}

int X509CompareDlg::compareCRL()
{
    int ret = 0;
    int i = 0;

    BIN binFinger = {0,0};

    char    sThisUpdate[64];
    char    sNextUpdate[64];

    JCRLInfo ACRLInfo;
    JCRLInfo BCRLInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    memset( &ACRLInfo, 0x00, sizeof(JCRLInfo));
    memset( &BCRLInfo, 0x00, sizeof(JCRLInfo));
    ret = JS_PKI_getCRLInfo( &A_bin_, &ACRLInfo, &pAExtList, NULL );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_PKI_getCRLInfo( &B_bin_, &BCRLInfo, &pBExtList, NULL );
    if( ret != 0 )
    {
        goto end;
    }

    JS_PKI_genHash( "SHA1", &A_bin_, &binFinger );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(ACRLInfo.nVersion+1)));
    i++;

    if( ACRLInfo.pIssuerName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("IssuerName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pIssuerName)));
        i++;
    }


    JS_UTIL_getDateTime( ACRLInfo.uThisUpdate, sThisUpdate );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("ThisUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sThisUpdate)));
    i++;

    JS_UTIL_getDateTime( ACRLInfo.uNextUpdate, sNextUpdate );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NextUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdate)));
    i++;

    if( ACRLInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("SignAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pSignAlgorithm)));
        i++;
    }

    if( ACRLInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pSignature)));
        i++;
    }

    if( pAExtList )
    {
        JExtensionInfoList *pCurList = pAExtList;

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

            mCompareTable->insertRow(i);
            mCompareTable->setRowHeight(i,10);
            mCompareTable->setItem(i,0, CRLInfoDlg::getExtNameItem(strSN));
            mCompareTable->setItem(i,1, item );

            pCurList = pCurList->pNext;
            i++;
        }
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFinger.pVal, binFinger.nLen))));
    i++;

end :
    JS_PKI_resetCRLInfo( &ACRLInfo );
    JS_PKI_resetCRLInfo( &BCRLInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binFinger );
}

int X509CompareDlg::compareCSR()
{
    int ret = 0;
    int i = 0;

    BIN binPub = {0,0};

    JReqInfo AReqInfo;
    JReqInfo BReqInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    memset( &AReqInfo, 0x00, sizeof(JReqInfo));
    memset( &BReqInfo, 0x00, sizeof(JReqInfo));

    ret = JS_PKI_getReqInfo( &A_bin_, &AReqInfo, 0, &pAExtList );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_PKI_getReqInfo( &B_bin_, &BReqInfo, 0, &pBExtList );
    if( ret != 0 )
    {
        goto end;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(AReqInfo.nVersion + 1)));
    i++;

    if( AReqInfo.pSubjectDN )
    {
        QString name = QString::fromUtf8( AReqInfo.pSubjectDN );

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Verify")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.bVerify ? "Verify" : "Not Verify")));
    i++;

    if( AReqInfo.pPublicKey )
    {
        int nKeyType = -1;
        int nOption = -1;

        QString strAlg;
        QString strParam;

        JS_BIN_decodeHex( AReqInfo.pPublicKey, &binPub );
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

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));

        if( strParam.length() > 0 )
            item = new QTableWidgetItem(QString("%1 (%2)").arg( strAlg ).arg( strParam ));
        else
            item = new QTableWidgetItem(QString("%1").arg(strAlg));

        item->setData( Qt::UserRole, QString( AReqInfo.pPublicKey ) );
        mCompareTable->setItem( i, 1, item );
        i++;
    }

    if( AReqInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pSignAlgorithm)));
        i++;
    }

    if( AReqInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pSignature)));
        i++;
    }

    if( AReqInfo.pChallenge )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Challenge")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pChallenge)));
        i++;
    }

    if( AReqInfo.pUnstructuredName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("UnstructuredName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pUnstructuredName)));
        i++;
    }


    if( pAExtList )
    {
        JExtensionInfoList *pCurList = pAExtList;

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

            mCompareTable->insertRow(i);
            mCompareTable->setRowHeight(i,10);

            mCompareTable->setItem(i,0, CSRInfoDlg::getExtNameItem( strSN ));
            mCompareTable->setItem(i, 1, item );


            pCurList = pCurList->pNext;
            i++;
        }
    }

end :
    JS_PKI_resetReqInfo( &AReqInfo );
    JS_PKI_resetReqInfo( &BReqInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binPub );
}

void X509CompareDlg::clickCompare()
{
    int ret = 0;

    QString strAPath = mAPathText->text();
    QString strBPath = mBPathText->text();

    if( strAPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a A file" ), this );
        return;
    }

    if( strBPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a B file" ), this );
        return;
    }


    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );

    JS_BIN_fileReadBER( strAPath.toLocal8Bit().toStdString().c_str(), &A_bin_ );
    JS_BIN_fileReadBER( strBPath.toLocal8Bit().toStdString().c_str(), &B_bin_ );

    if( mTypeCombo->currentIndex() == 0 ) // Certificate
    {
        compareCert();
    }
    else if( mTypeCombo->currentIndex() == 1 ) // CRL
    {
        compareCRL();
    }
    else if( mTypeCombo->currentIndex() == 2 ) // CSR
    {
        compareCSR();
    }

end :

}
