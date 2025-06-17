#include "x509_compare_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "csr_info_dlg.h"
#include "cert_man_dlg.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_pvd.h"
#include "js_pki_tools.h"
#include "js_util.h"

const QString kValidIcon = ":/images/valid.png";
const QString kInvalidIcon = ":/images/invalid.png";

X509CompareDlg::X509CompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    memset( &A_bin_, 0x00, sizeof(BIN));
    memset( &B_bin_, 0x00, sizeof(BIN));

    initUI();

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType()));

    connect( mShowInfoBtn, SIGNAL(clicked()), this, SLOT(clickShowInfo()));
    connect( mCompareTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCompareTable(QModelIndex)));
    connect( mCompareTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(dblClickTable()));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAFindBtn, SIGNAL(clicked()), this, SLOT(clickAFind()));
    connect( mBFindBtn, SIGNAL(clicked()), this, SLOT(clickBFind()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mCompareBtn, SIGNAL(clicked()), this, SLOT(clickCompare()));

    connect( mAViewBtn, SIGNAL(clicked()), this, SLOT(clickViewA()));
    connect( mADecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecodeA()));
    connect( mBViewBtn, SIGNAL(clicked()), this, SLOT(clickViewB()));
    connect( mBDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecodeB()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mAViewBtn->setFixedWidth(34);
    mADecodeBtn->setFixedWidth(34);
    mBViewBtn->setFixedWidth(34);
    mBDecodeBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mCompareBtn->setDefault(true);
}

X509CompareDlg::~X509CompareDlg()
{
    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );
}

void X509CompareDlg::changeType()
{
    QString strType = mTypeCombo->currentText();
    mTitleLabel->setText( tr( "%1 comparision" ).arg( strType ));
    mAPathLabel->setText( tr( "A %1 Path" ).arg( strType ));
    mBPathLabel->setText( tr( "B %1 Path" ).arg( strType ));

    mCompareTable->horizontalHeaderItem(1)->setText( tr("A %1 value").arg( strType ));
    mCompareTable->horizontalHeaderItem(2)->setText( tr("B %1 value").arg( strType ));
}

void X509CompareDlg::initUI()
{
    QStringList sTypeList = { tr("Certificate" ), tr( "CRL" ), tr( "CSR" ) };
    QStringList sBaseLabels = { tr("Field"), tr("A Certificate value"), tr( "B Certificate value" ) };

    mCompareTable->clear();
    mCompareTable->horizontalHeader()->setStretchLastSection(true);
    mCompareTable->setColumnCount(sBaseLabels.size());
    mCompareTable->setHorizontalHeaderLabels( sBaseLabels );
    mCompareTable->verticalHeader()->setVisible(false);
    mCompareTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCompareTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCompareTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCompareTable->setColumnWidth( 0, 140 );
    mCompareTable->setColumnWidth( 1, 280 );

    mTypeCombo->addItems( sTypeList );
    mResBtn->setIcon( QIcon( ":/images/compare.png" ));

    mAPathText->setPlaceholderText( tr("Find file A") );
    mBPathText->setPlaceholderText( tr("Find file B") );
    mAInfoText->setPlaceholderText( tr( "A field value" ));
    mBInfoText->setPlaceholderText( tr( "B field value" ));
}


void X509CompareDlg::initialize()
{

}

void X509CompareDlg::logA( const QString strLog, QColor cr )
{
    QTextCursor cursor = mAInfoText->textCursor();
    //    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    //cursor.insertText( "\n" );

    mAInfoText->setTextCursor( cursor );
    mAInfoText->repaint();
}

void X509CompareDlg::elogA( const QString strLog )
{
    logA( strLog, QColor(0xFF,0x00,0x00));
}

void X509CompareDlg::logB( const QString strLog, QColor cr )
{
    QTextCursor cursor = mBInfoText->textCursor();
    //    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    //cursor.insertText( "\n" );

    mBInfoText->setTextCursor( cursor );
    mBInfoText->repaint();
}

void X509CompareDlg::elogB( const QString strLog )
{
    logB( strLog, QColor(0xFF,0x00,0x00));
}

void X509CompareDlg::logAB( const QString strLog, QColor cr )
{
    logA( strLog, cr );
    logB( strLog, cr );
}

void X509CompareDlg::elogAB( const QString strLog )
{
    elogA( strLog );
    elogB( strLog );
}

void X509CompareDlg::clickAFind()
{
    int nFileType = JS_FILE_TYPE_CERT;
    QString strPath = mAPathText->text();

    if( mTypeCombo->currentIndex() == 1 )
        nFileType = JS_FILE_TYPE_CRL;
    else if( mTypeCombo->currentIndex() == 2 )
        nFileType = JS_FILE_TYPE_CSR;

    QString strFilePath = berApplet->findFile( this, nFileType, strPath );

    if( strFilePath.length() > 0 )
    {
        mAPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickBFind()
{
    int nFileType = JS_FILE_TYPE_CERT;
    QString strPath = mBPathText->text();

    if( mTypeCombo->currentIndex() == 1 )
        nFileType = JS_FILE_TYPE_CRL;
    else if( mTypeCombo->currentIndex() == 2 )
        nFileType = JS_FILE_TYPE_CSR;

    QString strFilePath = berApplet->findFile( this, nFileType, strPath );

    if( strFilePath.length() > 0 )
    {
        mBPathText->setText( strFilePath );
    }
}

void X509CompareDlg::clickClear()
{
    mCompareTable->setRowCount(0);
    mAInfoText->clear();
    mBInfoText->clear();
    mCompareLabel->setText( tr( "Not Compared" ));
    mResBtn->setIcon( QIcon( ":/images/compare.png" ));

    JS_BIN_reset( &A_bin_ );
    JS_BIN_reset( &B_bin_ );
    bin_type_ = -1;
}

int X509CompareDlg::compareExt( const JExtensionInfoList *pAExtList, const JExtensionInfoList *pBExtList )
{
    QString strIcon;
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
            {
                item->setIcon(QIcon(":/images/critical.png"));
                item->setData( Qt::UserRole, "critical" );
            }
            else
            {
                item->setIcon(QIcon(":/images/normal.png"));
                item->setData( Qt::UserRole, "non-critical" );
            }

            mCompareTable->insertRow(i);
            mCompareTable->setRowHeight(i,10);
            mCompareTable->setItem(i, 0, CertInfoDlg::getExtNameItem(strSN));
            mCompareTable->setItem(i, 1, item );

            if( pFindList )
            {
                strValue.clear();

                getInfoValue( &pFindList->sExtensionInfo, strValue );
                QTableWidgetItem *item2 = new QTableWidgetItem( strValue );

                if( pFindList->sExtensionInfo.bCritical )
                {
                    item2->setIcon(QIcon(":/images/critical.png"));
                    item2->setData( Qt::UserRole, "critical" );
                }
                else
                {
                    item2->setIcon(QIcon(":/images/normal.png"));
                    item2->setData( Qt::UserRole, "non-critical" );
                }

                mCompareTable->setItem(i, 2, item2 );

                if( pCurList->sExtensionInfo.bCritical == pFindList->sExtensionInfo.bCritical &&
                    QString( pCurList->sExtensionInfo.pValue ) == QString( pFindList->sExtensionInfo.pValue ))
                {
                    mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
                    strIcon = kValidIcon;
                }
                else
                {
                    mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
                    strIcon = kInvalidIcon;
                }

                mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
            }
            else
            {
                strIcon = kInvalidIcon;
                mCompareTable->setItem(i, 2, new QTableWidgetItem( "" ) );
                mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
                mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
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
                mCompareTable->setItem( i, 1, new QTableWidgetItem( "" ));
                mCompareTable->setItem(i, 2, item );

                strIcon = kInvalidIcon;
                mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
                mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
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

    QString strIcon;

    memset( &ACertInfo, 0x00, sizeof(JCertInfo));
    memset( &BCertInfo, 0x00, sizeof(JCertInfo));

    ret = JS_PKI_getCertInfo( &A_bin_, &ACertInfo, &pAExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File A is not a certificate" ), this );
        goto end;
    }

    ret = JS_PKI_getCertInfo( &B_bin_, &BCertInfo, &pBExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File B is not a certificate" ), this );
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
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));

    i++;

    if( ACertInfo.pSerial )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Serial")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACertInfo.pSerial)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCertInfo.pSerial)));

        if( QString( ACertInfo.pSerial ) == QString( BCertInfo.pSerial ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    JS_UTIL_getDateTime( ACertInfo.uNotAfter, sNotAfterA );
    JS_UTIL_getDateTime( BCertInfo.uNotAfter, sNotAfterB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NotAfter")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfterA)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(sNotAfterB)));

    if( QString( sNotAfterA ) == QString( sNotAfterB ) )
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));

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
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerA.pVal, binFingerA.nLen))));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerB.pVal, binFingerB.nLen))));

    if( JS_BIN_cmp( &binFingerA, &binFingerB ) == 0 )
    {
        strIcon = kValidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        mCompareLabel->setText( tr( "A and B %1 are the same" ).arg( mTypeCombo->currentText() ));
    }
    else
    {
        strIcon = kInvalidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        mCompareLabel->setText( tr( "A and B %1 are different" ).arg( mTypeCombo->currentText() ));
    }

    mResBtn->setIcon( QIcon(strIcon));
    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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

    QString strIcon;

    memset( &ACRLInfo, 0x00, sizeof(JCRLInfo));
    memset( &BCRLInfo, 0x00, sizeof(JCRLInfo));
    ret = JS_PKI_getCRLInfo( &A_bin_, &ACRLInfo, &pAExtList, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File A is not a CRL" ), this );
        goto end;
    }

    ret = JS_PKI_getCRLInfo( &B_bin_, &BCRLInfo, &pBExtList, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File B is not a CRL" ), this );
        goto end;
    }

    JS_PKI_genHash( "SHA1", &A_bin_, &binFingerA );
    JS_PKI_genHash( "SHA1", &B_bin_, &binFingerB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(ACRLInfo.nVersion+1)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("V%1").arg(BCRLInfo.nVersion + 1)));

    if( ACRLInfo.nVersion == BCRLInfo.nVersion )
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    if( ACRLInfo.pIssuerName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("IssuerName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pIssuerName)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCRLInfo.pIssuerName)));
        if( QString( ACRLInfo.pIssuerName ) == QString( BCRLInfo.pIssuerName ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }


    JS_UTIL_getDateTime( ACRLInfo.uThisUpdate, sThisUpdateA );
    JS_UTIL_getDateTime( BCRLInfo.uThisUpdate, sThisUpdateB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("ThisUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sThisUpdateA)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(sThisUpdateB)));
    if( ACRLInfo.uThisUpdate == BCRLInfo.uThisUpdate )
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    JS_UTIL_getDateTime( ACRLInfo.uNextUpdate, sNextUpdateA );
    JS_UTIL_getDateTime( BCRLInfo.uNextUpdate, sNextUpdateB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("NextUpdate")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdateA)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(sNextUpdateB)));
    if( ACRLInfo.uNextUpdate == BCRLInfo.uNextUpdate )
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    if( ACRLInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("SignAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pSignAlgorithm)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCRLInfo.pSignAlgorithm)));
        if( QString( ACRLInfo.pSignAlgorithm ) == QString( BCRLInfo.pSignAlgorithm ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( ACRLInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(ACRLInfo.pSignature)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BCRLInfo.pSignature)));

        if( QString( ACRLInfo.pSignature ) == QString( BCRLInfo.pSignature ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerA.pVal, binFingerA.nLen))));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerB.pVal, binFingerB.nLen))));

    if( JS_BIN_cmp( &binFingerA, &binFingerB ) == 0 )
    {
        strIcon = kValidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        mCompareLabel->setText( tr( "A and B %1 are the same" ).arg( mTypeCombo->currentText() ));
    }
    else
    {
        strIcon = kInvalidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        mCompareLabel->setText( tr( "A and B %1 are different" ).arg( mTypeCombo->currentText() ));
    }

    mResBtn->setIcon( QIcon(strIcon));
    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
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

    BIN binFingerA = {0,0};
    BIN binFingerB = {0,0};

    JReqInfo AReqInfo;
    JReqInfo BReqInfo;

    JExtensionInfoList *pAExtList = NULL;
    JExtensionInfoList *pBExtList = NULL;

    QString strIcon;

    memset( &AReqInfo, 0x00, sizeof(JReqInfo));
    memset( &BReqInfo, 0x00, sizeof(JReqInfo));

    ret = JS_PKI_getReqInfo( &A_bin_, &AReqInfo, 0, &pAExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File A is not a CSR" ), this );
        goto end;
    }

    ret = JS_PKI_getReqInfo( &B_bin_, &BReqInfo, 0, &pBExtList );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "File B is not a CSR" ), this );
        goto end;
    }

    JS_PKI_genHash( "SHA1", &A_bin_, &binFingerA );
    JS_PKI_genHash( "SHA1", &B_bin_, &binFingerB );

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(AReqInfo.nVersion + 1)));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("V%1").arg(BReqInfo.nVersion + 1)));

    if( AReqInfo.nVersion == BReqInfo.nVersion )
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        strIcon = kValidIcon;
    }
    else
    {
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        strIcon = kInvalidIcon;
    }

    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    if( AReqInfo.pSubjectDN )
    {
        QString nameA = QString::fromUtf8( AReqInfo.pSubjectDN );
        QString nameB = QString::fromUtf8( BReqInfo.pSubjectDN );

        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( nameA )));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg( nameB )));

        if( nameA == nameB )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( AReqInfo.pPublicKey )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pPublicKey)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BReqInfo.pPublicKey)));

        if( QString( AReqInfo.pPublicKey ) == QString( BReqInfo.pPublicKey ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( AReqInfo.pSignAlgorithm )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pSignAlgorithm)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BReqInfo.pSignAlgorithm)));

        if( QString( AReqInfo.pSignAlgorithm ) == QString( BReqInfo.pSignAlgorithm ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( AReqInfo.pSignature )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pSignature)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BReqInfo.pSignature)));

        if( QString( AReqInfo.pSignature ) == QString( BReqInfo.pSignature ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( AReqInfo.pChallenge )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("Challenge")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pChallenge)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BReqInfo.pChallenge)));

        if( QString( AReqInfo.pChallenge ) == QString( BReqInfo.pChallenge ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    if( AReqInfo.pUnstructuredName )
    {
        mCompareTable->insertRow(i);
        mCompareTable->setRowHeight(i,10);
        mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("UnstructuredName")));
        mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(AReqInfo.pUnstructuredName)));
        mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(BReqInfo.pUnstructuredName)));

        if( QString( AReqInfo.pUnstructuredName ) == QString( BReqInfo.pUnstructuredName ) )
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
            strIcon = kValidIcon;
        }
        else
        {
            mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
            strIcon = kInvalidIcon;
        }

        mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
        i++;
    }

    mCompareTable->insertRow(i);
    mCompareTable->setRowHeight(i,10);
    mCompareTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCompareTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerA.pVal, binFingerA.nLen))));
    mCompareTable->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(getHexString(binFingerB.pVal, binFingerB.nLen))));

    if( JS_BIN_cmp( &binFingerA, &binFingerB ) == 0 )
    {
        strIcon = kValidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 0);
        mCompareLabel->setText( tr( "A and B %1 are the same" ).arg( mTypeCombo->currentText() ));
    }
    else
    {
        strIcon = kInvalidIcon;
        mCompareTable->item(i,0)->setData(Qt::UserRole, 1);
        mCompareLabel->setText( tr( "A and B %1 are different" ).arg( mTypeCombo->currentText() ));
    }

    mResBtn->setIcon( QIcon(strIcon));
    mCompareTable->item( i, 0 )->setIcon( QIcon( strIcon ));
    i++;

    compareExt( pAExtList, pBExtList );

end :
    JS_PKI_resetReqInfo( &AReqInfo );
    JS_PKI_resetReqInfo( &BReqInfo );

    if( pAExtList ) JS_PKI_resetExtensionInfoList( &pAExtList );
    if( pBExtList ) JS_PKI_resetExtensionInfoList( &pBExtList );

    JS_BIN_reset( &binFingerA );
    JS_BIN_reset( &binFingerB );
}

void X509CompareDlg::clickCompare()
{
    int ret = 0;

    QString strAPath = mAPathText->text();
    QString strBPath = mBPathText->text();



    if( strAPath.length() < 1 )
    {
        if( mTypeCombo->currentIndex() == 0 || mTypeCombo->currentIndex() == 1 )
        {
            CertManDlg certMan;
            QString strCertHex;

            if( mTypeCombo->currentIndex() == 0 )
                certMan.setMode(ManModeSelCert);
            else
                certMan.setMode(ManModeSelCRL );

            certMan.setTitle( tr( "Select a A %1").arg( mTypeCombo->currentText()) );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            JS_BIN_reset( &A_bin_ );
            strCertHex = certMan.getCertHex();
            JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &A_bin_ );
        }

        if( A_bin_.nLen < 1 )
        {
            berApplet->warningBox( tr( "Find a A file" ), this );
            return;
        }
    }
    else
    {
        JS_BIN_reset( &B_bin_ );
        JS_BIN_fileReadBER( strAPath.toLocal8Bit().toStdString().c_str(), &A_bin_ );
    }

    if( strBPath.length() < 1 )
    {
        if( mTypeCombo->currentIndex() == 0 || mTypeCombo->currentIndex() == 1 )
        {
            CertManDlg certMan;
            QString strCertHex;

            if( mTypeCombo->currentIndex() == 0 )
                certMan.setMode(ManModeSelCert);
            else
                certMan.setMode(ManModeSelCRL );

            certMan.setTitle( tr( "Select a B %1").arg( mTypeCombo->currentText()) );

            if( certMan.exec() != QDialog::Accepted )
                goto end;

            JS_BIN_reset( &B_bin_ );
            strCertHex = certMan.getCertHex();
            JS_BIN_decodeHex( strCertHex.toStdString().c_str(), &B_bin_ );
        }

        if( B_bin_.nLen < 1 )
        {
            berApplet->warningBox( tr( "Find a B file" ), this );
            return;
        }
    }
    else
    {
        JS_BIN_reset( &B_bin_ );
        JS_BIN_fileReadBER( strBPath.toLocal8Bit().toStdString().c_str(), &B_bin_ );
    }

    mCompareTable->setRowCount(0);
    bin_type_ = mTypeCombo->currentIndex();

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
    return;
}

void X509CompareDlg::clickShowInfo()
{
    mInfoDock->show();
}

void X509CompareDlg::clickCompareTable( QModelIndex index )
{
    int row = index.row();
    QString strInfoA;
    QString strInfoB;

    QString strLine = QString( "=======================================\n" );
    QString strLine2 = QString( "---------------------------------------\n" );

    QTableWidgetItem *item0 = mCompareTable->item( row, 0 );
    QTableWidgetItem* item1 = mCompareTable->item( row, 1 );
    QTableWidgetItem* item2 = mCompareTable->item( row, 2 );

    QString strCritA;
    QString strCritB;
    QString strValueA;
    QString strValueB;

    mAInfoText->clear();
    mBInfoText->clear();

    if( item0 == NULL || item1 == NULL || item2 == NULL) return;

    strCritA = item1->data(Qt::UserRole).toString();
    strCritB = item2->data(Qt::UserRole).toString();

    strValueA = item1->text();
    strValueB = item2->text();


    logAB( strLine );
    logAB( QString( "== %1\n").arg( item0->text() ) );
    logAB( strLine );

    logA( QString( "-- A value" ) );

    if( strCritA.length() > 0 )
    {
        if( strCritA == strCritB )
            logA( QString( " [%1]" ).arg( strCritA ));
        else
            elogA( QString( " [%1]" ).arg( strCritA ));
    }

    logA( "\n" );
    logA( strLine2 );

    if( strValueA == strValueB )
        logA( QString( "%1\n" ).arg( strValueA ) );
    else
        elogA( QString( "%1\n" ).arg( strValueA ) );

    logA( strLine );


    logB( QString( "-- B value" ) );

    if( strCritB.length() > 0 )
    {
        if( strCritA == strCritB )
            logB( QString( " [%1]" ).arg( strCritB ) );
        else
            elogB( QString( " [%1]" ).arg( strCritB ) );
    }

    logB( "\n" );
    logB( strLine2 );

    if( strValueA == strValueB )
        logB( QString( "%1\n" ).arg( strValueB ) );
    else
        elogB( QString( "%1\n" ).arg( strValueB ) );

    logB( strLine );
}

void X509CompareDlg::dblClickTable()
{
    QTableWidgetItem* item = mCompareTable->currentItem();

    if( item == NULL ) return;

    int col = item->column();

    if( col == 1 )
    {
        if( bin_type_ == 0 )
        {
            CertInfoDlg certInfo;
            certInfo.setCertBIN( &A_bin_ );
            certInfo.exec();
        }
        else if( bin_type_ == 1 )
        {
            CRLInfoDlg crlInfo;
            crlInfo.setCRL_BIN( &A_bin_ );
        }
        else if( bin_type_ == 2 )
        {
            CSRInfoDlg csrInfo;
            csrInfo.setReqBIN( &A_bin_ );
            csrInfo.exec();
        }
    }
    else if( col == 2 )
    {
        if( bin_type_ == 0 )
        {
            CertInfoDlg certInfo;
            certInfo.setCertBIN( &B_bin_ );
            certInfo.exec();
        }
        else if( bin_type_ == 1 )
        {
            CRLInfoDlg crlInfo;
            crlInfo.setCRL_BIN( &B_bin_ );
        }
        else if( bin_type_ == 2 )
        {
            CSRInfoDlg csrInfo;
            csrInfo.setReqBIN( &B_bin_ );
            csrInfo.exec();
        }
    }
}

void X509CompareDlg::clickViewA()
{
    QString strPath = mAPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a %1").arg( mTypeCombo->currentText()), this );
        mAPathText->setFocus();
        return;
    }

    if( mTypeCombo->currentIndex() == 1 )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRLPath( strPath );
        crlInfo.exec();
    }
    else if( mTypeCombo->currentIndex() == 2 )
    {
        CSRInfoDlg csrInfo;
        csrInfo.setReqPath( strPath );
        csrInfo.exec();
    }
    else
    {
        CertInfoDlg certInfoDlg;
        certInfoDlg.setCertPath( strPath );
        certInfoDlg.exec();
    }
}

void X509CompareDlg::clickDecodeA()
{
    BIN binData = {0,0};
    QString strPath = mAPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a %1").arg( mTypeCombo->currentText()), this );
        mAPathText->setFocus();
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

void X509CompareDlg::clickViewB()
{
    QString strPath = mBPathText->text();
    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a %1").arg( mTypeCombo->currentText()), this );
        mBPathText->setFocus();
        return;
    }

    if( mTypeCombo->currentIndex() == 1 )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRLPath( strPath );
        crlInfo.exec();
    }
    else if( mTypeCombo->currentIndex() == 2 )
    {
        CSRInfoDlg csrInfo;
        csrInfo.setReqPath( strPath );
        csrInfo.exec();
    }
    else
    {
        CertInfoDlg certInfoDlg;
        certInfoDlg.setCertPath( strPath );
        certInfoDlg.exec();
    }
}

void X509CompareDlg::clickDecodeB()
{
    BIN binData = {0,0};
    QString strPath = mBPathText->text();

    if( strPath.length() < 1 )
    {
        berApplet->warningBox( tr("Select a %1").arg( mTypeCombo->currentText()), this );
        mBPathText->setFocus();
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
