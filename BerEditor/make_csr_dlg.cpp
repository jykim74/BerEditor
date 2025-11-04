#include <QAction>
#include <QMenu>

#include "make_csr_dlg.h"
#include "common.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_error.h"

#include "ber_applet.h"

#include "settings_mgr.h"
#include "one_list_dlg.h"

const QStringList kRDNList = {
    "emailAddress", "CN", "OU", "O",
    "L", "ST", "C"
};

MakeCSRDlg::MakeCSRDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &csr_, 0x00, sizeof(BIN));
    memset( &pri_key_, 0x00, sizeof(BIN));

    connect( mRDNTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotTableMenuRequested(QPoint)));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mEMAILADDRESSText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCNText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mOUText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mLText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mSTText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mCText, SIGNAL(textChanged(QString)), this, SLOT(changeDN()));
    connect( mSANListBtn, SIGNAL(clicked()), this, SLOT(clickSANList()));
    connect( mRDNAddBtn, SIGNAL(clicked()), this, SLOT(clickRDNAdd()));

    initialize();
    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCSRDlg::~MakeCSRDlg()
{
    JS_BIN_reset( &csr_ );
    JS_BIN_reset( &pri_key_ );
}

void MakeCSRDlg::initUI()
{
    mRDNNameCombo->setEditable(true);
    mRDNNameCombo->addItems( kRDNList );

    QStringList sBaseLabels = { tr("Name"), tr("Value") };

    mRDNTable->clear();
    mRDNTable->horizontalHeader()->setStretchLastSection(true);
    mRDNTable->setColumnCount(sBaseLabels.size());
    mRDNTable->setHorizontalHeaderLabels( sBaseLabels );
    mRDNTable->verticalHeader()->setVisible(false);
    mRDNTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRDNTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mRDNTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRDNTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void MakeCSRDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mSignHashCombo->addItems( kHashList );
    mSignHashCombo->setCurrentText( setMgr->defaultHash() );
    mSANListBtn->hide();
    mCNText->setFocus();
}

void MakeCSRDlg::setPriKey( const BIN *pPri )
{
    int nKeyType = JS_PKI_getPriKeyType( pPri );

    if( nKeyType < 0 ) return;

    if( nKeyType == JS_PKI_KEY_TYPE_EDDSA ||
        nKeyType == JS_PKI_KEY_TYPE_ML_DSA ||
        nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
    {
        mSignHashCombo->setEnabled( false );
        mSignHashLabel->setEnabled( false );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_SM2 )
    {
        mSignHashCombo->clear();
        mSignHashCombo->addItem( "SM3" );
    }

    JS_BIN_reset( &pri_key_ );
    JS_BIN_copy( &pri_key_, pPri );
}

const QString MakeCSRDlg::getCSRHex()
{
    return getHexString( &csr_ );
}

void MakeCSRDlg::setInfo( const QString strInfo )
{
    mInfoLabel->setText( strInfo );
}

void MakeCSRDlg::setSAN( const QStringList listSAN )
{
    san_list_.clear();
    san_list_ = listSAN;

    mSANListBtn->show();
}

const QString MakeCSRDlg::getDN()
{
    QString strEmailAddress = mEMAILADDRESSText->text();
    QString strCN = mCNText->text();
    QString strO = mOText->text();
    QString strOU = mOUText->text();
    QString strL = mLText->text();
    QString strST = mSTText->text();
    QString strC = mCText->text();


    QString strRDN_Email;
    QString strRDN_CN;
    QString strRDN_OU;
    QString strRDN_O;
    QString strRDN_L;
    QString strRDN_ST;
    QString strRDN_C;
    QString strRDN_More;


    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        strRDN_Email = QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        strRDN_CN = QString( "CN=%1").arg( strCN );
    }

    if( strOU.length() > 0 )
    {
        strRDN_OU = QString( "OU=%1").arg( strOU );
    }

    if( strO.length() > 0 )
    {
        strRDN_O = QString( "O=%1").arg( strO );
    }

    if( strL.length() > 0 )
    {
        strRDN_L = QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        strRDN_ST = QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        strRDN_C = QString( "C=%1" ).arg( strC );
    }

    int nCount = mRDNTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        QTableWidgetItem *item0 = mRDNTable->item(i, 0);
        QTableWidgetItem *item1 = mRDNTable->item(i, 1);

        QString strName = item0->text();
        QString strValue = item1->text();

        if( strName == "emailAddress" )
        {
            if( strRDN_Email.length() > 0 ) strRDN_Email += ",";
            strRDN_Email += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "CN" )
        {
            if( strRDN_CN.length() > 0 ) strRDN_CN += ",";
            strRDN_CN += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "OU" )
        {
            if( strRDN_OU.length() > 0 ) strRDN_OU += ",";
            strRDN_OU += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "O" )
        {
            if( strRDN_O.length() > 0 ) strRDN_O += ",";
            strRDN_O += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "L" )
        {
            if( strRDN_L.length() > 0 ) strRDN_L += ",";
            strRDN_L += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "ST" )
        {
            if( strRDN_ST.length() > 0 ) strRDN_ST += ",";
            strRDN_ST += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else if( strName == "C" )
        {
            if( strRDN_C.length() > 0 ) strRDN_C += ",";
            strRDN_C += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
        else
        {
            if( strRDN_More.length() > 0 ) strRDN_More += ",";
            strRDN_More += QString( "%1=%2" ).arg( strName ).arg(strValue);
        }
    }

    if( strRDN_More.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_More;
    }

    if( strRDN_Email.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_Email;
    }

    if( strRDN_CN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_CN;
    }

    if( strRDN_OU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_OU;
    }

    if( strRDN_O.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_O;
    }

    if( strRDN_L.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_L;
    }

    if( strRDN_ST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_ST;
    }

    if( strRDN_C.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += strRDN_C;
    }

    return strDN;
}

void MakeCSRDlg::clickClear()
{
    mEMAILADDRESSText->clear();
    mCNText->clear();
    mOText->clear();
    mOUText->clear();
    mLText->clear();
    mSTText->clear();
    mCText->clear();

    mRDNValueText->clear();
    mRDNTable->setRowCount(0);
}

void MakeCSRDlg::changeDN()
{
    QString strDN = getDN();
    mDNText->setText( strDN );
}

void MakeCSRDlg::clickSANList()
{
    QString strName;
    OneListDlg oneList;

    for( int i = 0; i < san_list_.size(); i++ )
    {
        if( i != 0 ) strName += "#";
        strName += san_list_.at(i);
    }

    oneList.addName( strName );
    if( oneList.exec() == QDialog::Accepted )
    {
        san_list_ = oneList.getList();
    }
}

void MakeCSRDlg::clickRDNAdd()
{
    QString strName = mRDNNameCombo->currentText();
    QString strValue = mRDNValueText->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mRDNNameCombo->setFocus();
        return;
    }

    if( strValue.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a value" ), this );
        mRDNValueText->setFocus();
        return;
    }

    mRDNTable->insertRow(0);
    mRDNTable->setRowHeight(0, 10);
    mRDNTable->setItem( 0, 0, new QTableWidgetItem( strName ));
    mRDNTable->setItem( 0, 1, new QTableWidgetItem( strValue ));

    mRDNValueText->clear();
    changeDN();
}

void MakeCSRDlg::deleteRDN()
{
    QModelIndex idx = mRDNTable->currentIndex();
    QTableWidgetItem* item = mRDNTable->item( idx.row(), 0 );

    if( item )
    {
        mRDNTable->removeRow( idx.row() );
        changeDN();
    }
}

void MakeCSRDlg::slotTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction* deleteAct = new QAction( tr( "Delete" ), this );

    connect( deleteAct, SIGNAL(triggered()), this, SLOT(deleteRDN()));

    menu->addAction( deleteAct );
    menu->popup( mRDNTable->viewport()->mapToGlobal(pos));
}

void MakeCSRDlg::clickOK()
{
    int ret = 0;
    QString strHash = mSignHashCombo->currentText();
    QString strDN = getDN();
    JExtensionInfoList *pExtList = NULL;

    if( strDN.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert DN"), this );
        mCNText->setFocus();
        return;
    }

    JS_BIN_reset( &csr_ );

    if( san_list_.size() > 0 )
    {
        JExtensionInfo sExtInfo;
        JDB_ProfileExt sDBProfile;
        QString strValue;
        memset( &sDBProfile, 0x00, sizeof(sDBProfile));
        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        for( int i = 0; i < san_list_.size(); i++ )
        {
            if( i != 0 ) strValue += "#";
            strValue += "DNS$";
            strValue += san_list_.at(i);
        }

        sDBProfile.bCritical = 0;
        sDBProfile.pSN = JS_strdup( JS_PKI_ExtNameSAN );
        sDBProfile.pValue = JS_strdup( strValue.toStdString().c_str() );

        ret = JS_PKI_transExtensionFromDBRec( &sExtInfo, &sDBProfile );
        if( ret == 0 )
        {
            JS_PKI_addExtensionInfoList( &pExtList, &sExtInfo );
        }

        JS_PKI_resetExtensionInfo( &sExtInfo );
        JS_DB_resetProfileExt( &sDBProfile );
    }

    ret = JS_PKI_makeCSR(
        strHash.toStdString().c_str(),
        strDN.toStdString().c_str(),
        mChallengeText->text().length() > 0 ? mChallengeText->text().toStdString().c_str() : NULL,
        mUnstructuredText->text().length() > 0 ? mUnstructuredText->text().toStdString().c_str() : NULL,
        &pri_key_, pExtList, &csr_ );

    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );

    if( ret == 0 )
    {
        return QDialog::accept();
    }
    else
    {
        berApplet->warnLog( tr( "fail to make CSR: %1").arg( JERR(ret) ), this);
        return QDialog::reject();
    }
}
