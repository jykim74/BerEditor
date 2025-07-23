#include "make_csr_dlg.h"
#include "common.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "ber_applet.h"

#include "settings_mgr.h"
#include "one_list_dlg.h"

MakeCSRDlg::MakeCSRDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    memset( &csr_, 0x00, sizeof(BIN));
    memset( &pri_key_, 0x00, sizeof(BIN));

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

    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "CN=%1").arg( strCN );
    }

    if( strO.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "O=%1").arg( strO );
    }

    if( strOU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "OU=%1").arg( strOU );
    }

    if( strL.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "C=%1" ).arg( strC );
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
        NULL, NULL, &pri_key_, pExtList, &csr_ );

    if( pExtList ) JS_PKI_resetExtensionInfoList( &pExtList );

    if( ret == 0 )
    {
        return QDialog::accept();
    }
    else
    {
        berApplet->warnLog( tr( "fail to make CSR: %1").arg( ret ), this);
        return QDialog::reject();
    }
}
