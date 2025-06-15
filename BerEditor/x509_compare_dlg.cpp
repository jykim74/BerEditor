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

int X509CompareDlg::compareExt( const JExtensionInfoList *pAExtList, const JExtensionInfoList *pBExtList )
{
    QTableWidgetItem *iconItem = new QTableWidgetItem( "" );
    int i = mCompareTable->rowCount();

    if( pAExtList )
    {
        const JExtensionInfoList *pCurList = pAExtList;
        const JExtensionInfoList *pFindList = NULL;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            pFindList = JS_PKI_getExtensionBySN( strSN.toStdString().c_str(), pBExtList );

            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mCompareTable->insertRow(i);
            mCompareTable->setRowHeight(i,10);
            mCompareTable->setItem(i, 0, CertInfoDlg::getExtNameItem(strSN));
            mCompareTable->setItem(i, 1, item );

            if( pFindList )
            {
                getInfoValue( &pFindList->sExtensionInfo, strValue );
                QTableWidgetItem *item2 = new QTableWidgetItem( strValue );
                if( pFindList->sExtensionInfo.bCritical )
                    item2->setIcon(QIcon(":/images/critical.png"));
                else
                    item2->setIcon(QIcon(":/images/normal.png"));

                mCompareTable->setItem(i, 2, item2 );

                if( pCurList->sExtensionInfo.bCritical == pFindList->sExtensionInfo.bCritical &&
                    QString( pCurList->sExtensionInfo.pValue ) == QString( pFindList->sExtensionInfo.pValue ))
                    iconItem->setIcon( QIcon(":/images/valid.png" ));
                else
                    iconItem->setIcon( QIcon(":/images/invalid.png" ));

                mCompareTable->setItem(i, 3, iconItem );
            }
            else
            {
                iconItem->setIcon( QIcon(":/imagees/invalid.png" ));
                mCompareTable->setItem(i, 3, iconItem );
            }

            pCurList = pCurList->pNext;

            i++;
        }
    }

    if( pBExtList )
    {
        const JExtensionInfoList *pCurList = pBExtList;
        const JExtensionInfoList *pFindList = NULL;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            pFindList = JS_PKI_getExtensionBySN( strSN.toStdString().c_str(), pAExtList );
            if( pFindList == NULL )
            {
                QTableWidgetItem *item = new QTableWidgetItem( strValue );
                if( bCrit )
                    item->setIcon(QIcon(":/images/critical.png"));
                else
                    item->setIcon(QIcon(":/images/normal.png"));

                mCompareTable->insertRow(i);
                mCompareTable->setRowHeight(i,10);
                mCompareTable->setItem(i,0, CertInfoDlg::getExtNameItem(strSN));
                mCompareTable->setItem(i, 2, item );

                iconItem->setIcon( QIcon(":/imagees/invalid.png" ));
                mCompareTable->setItem(i, 3, iconItem );
                i++;
            }

            pCurList = pCurList->pNext;
        }
    }

    return 0;
}

int X509CompareDlg::compareCert()
{
    int i = 0;
    int ret = 0;

    JCertInfo ACertInfo;
    JCertInfo BCertInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    BIN binFingerA = {0,0};
    BIN binFingerB = {0,0};

    char    sNotBeforeA[64];
    char    sNotAfterA[64];

    char    sNotBeforeB[64];
    char    sNotAfterB[64];

    QTableWidgetItem *iconItem = new QTableWidgetItem( "" );

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

    JS_PKI_genHash( "SHA1", &A_bin_, &binFingerA );
    JS_PKI_genHash( "SHA1", &B_bin_, &binFingerB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(ACertInfo.nVersion + 1)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("V%1").arg(BCertInfo.nVersion + 1)));

    if( ACertInfo.nVersion == BCertInfo.nVersion )
        iconItem->setIcon( QIcon(":/images/valid.png" ));
    else
        iconItem->setIcon( QIcon(":/images/invalid.png" ));

    mCompareTable->setItem(i, 3, iconItem );

    i++;

    if( ACertInfo.pSerial )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSerial)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pSerial)));

        if( QString( ACertInfo.pSerial ) == QString( BCertInfo.pSerial ) )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );
        i++;
    }

    JS_UTIL_getDateTime( ACertInfo.uNotBefore, sNotBeforeA );
    JS_UTIL_getDateTime( BCertInfo.uNotBefore, sNotBeforeB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NotBefore")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBeforeA)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(sNotBeforeB)));

    if( QString( sNotBeforeA ) == QString( sNotBeforeB ) )
        iconItem->setIcon( QIcon(":/images/valid.png" ));
    else
        iconItem->setIcon( QIcon(":/images/invalid.png" ));

    mCompareTable->setItem(i, 3, iconItem );
    i++;

    JS_UTIL_getDateTime( ACertInfo.uNotAfter, sNotAfterA );
    JS_UTIL_getDateTime( BCertInfo.uNotAfter, sNotAfterB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfterA)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(sNotAfterB)));

    if( QString( sNotAfterA ) == QString( sNotAfterB ) )
        iconItem->setIcon( QIcon(":/images/valid.png" ));
    else
        iconItem->setIcon( QIcon(":/images/invalid.png" ));

    mCompareTable->setItem(i, 3, iconItem );
    i++;

    if( ACertInfo.pSubjectName )
    {
        QString nameA = QString::fromUtf8( ACertInfo.pSubjectName );
        QString nameB = QString::fromUtf8( BCertInfo.pSubjectName );

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( nameA )));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg( nameB )));

        if( nameA == nameB )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );
        i++;
    }

    if( ACertInfo.pPublicKey )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pPublicKey)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pPublicKey)));

        if( QString( ACertInfo.pPublicKey ) == QString( BCertInfo.pPublicKey ) )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );

        i++;
    }

    if( ACertInfo.pIssuerName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("IssuerName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pIssuerName)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pIssuerName)));

        if( QString( ACertInfo.pIssuerName ) == QString( BCertInfo.pIssuerName ) )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );
        i++;
    }

    if( ACertInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSignAlgorithm)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pSignAlgorithm)));

        if( QString( ACertInfo.pSignAlgorithm ) == QString( BCertInfo.pSignAlgorithm ) )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );
        i++;
    }

    if( ACertInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSignature)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pSignature)));

        if( QString( ACertInfo.pSignature ) == QString( BCertInfo.pSignature ) )
            iconItem->setIcon( QIcon(":/images/valid.png" ));
        else
            iconItem->setIcon( QIcon(":/images/invalid.png" ));

        mCompareTable->setItem(i, 3, iconItem );
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerA.pVal, binFingerA.nLen))));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerB.pVal, binFingerB.nLen))));

    if( JS_BIN_cmp( &binFingerA, &binFingerB ) == 0 )
        iconItem->setIcon( QIcon(":/images/valid.png" ));
    else
        iconItem->setIcon( QIcon(":/images/invalid.png" ));

    mCompareTable->setItem(i, 3, iconItem );
    i++;

    compareExt( pAExtList, pBExtList );

end :
    JS_PKI_resetCertInfo( &ACertInfo );
    JS_PKI_resetCertInfo( &BCertInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binFingerA );
    JS_BIN_reset( &binFingerB );
}

int X509CompareDlg::compareCRL()
{
    int ret = 0;
    int i = 0;

    BIN binFingerA = {0,0};
    BIN binFingerB = {0,0};

    char    sThisUpdateA[64];
    char    sNextUpdateA[64];

    char    sThisUpdateB[64];
    char    sNextUpdateB[64];

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

    JS_PKI_genHash( "SHA1", &A_bin_, &binFingerA );

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


    JS_UTIL_getDateTime( ACRLInfo.uThisUpdate, sThisUpdateA );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("ThisUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sThisUpdateA)));
    i++;

    JS_UTIL_getDateTime( ACRLInfo.uNextUpdate, sNextUpdateA );
    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NextUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdateA)));
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

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerA.pVal, binFingerA.nLen))));
    i++;

    compareExt( pAExtList, pBExtList );

end :
    JS_PKI_resetCRLInfo( &ACRLInfo );
    JS_PKI_resetCRLInfo( &BCRLInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binFingerA );
    JS_BIN_reset( &binFingerB );
}

int X509CompareDlg::compareCSR()
{
    int ret = 0;
    int i = 0;

    BIN binPubA = {0,0};
    BIN binPubB = {0,0};

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

        JS_BIN_decodeHex( AReqInfo.pPublicKey, &binPubA );
        JS_PKI_getPubKeyInfo( &binPubA, &nKeyType, &nOption );

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

    compareExt( pAExtList, pBExtList );

end :
    JS_PKI_resetReqInfo( &AReqInfo );
    JS_PKI_resetReqInfo( &BReqInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binPubA );
    JS_BIN_reset( &binPubB );
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
