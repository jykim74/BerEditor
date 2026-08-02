#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenu>

#include "acme_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "cert_man_dlg.h"
#include "pri_key_info_dlg.h"
#include "cert_id_dlg.h"
#include "key_pair_man_dlg.h"
#include "acme_object.h"
#include "make_csr_dlg.h"
#include "cert_man_dlg.h"
#include "csr_info_dlg.h"
#include "export_dlg.h"
#include "cert_info_dlg.h"
#include "new_passwd_dlg.h"
#include "json_tree_dlg.h"
#include "revoke_reason_dlg.h"
#include "chall_test_dlg.h"
#include "one_list_dlg.h"
#include "pri_key_info_dlg.h"
#include "sel_list_dlg.h"
#include "dns_check_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_error.h"
#include "js_pki_tools.h"

const QString kACMEUsedURL = "ACMEUsedURL";

const QStringList kMethodList = { "POST", "GET" };
const QStringList kParserList = { "dir", "error" };
const QStringList kIdentifierList = { "dns", "http" };

const QStringList kCmdList = {
    kCmdDirectory, kCmdLocation, kCmdAccount, kCmdOrder,
    kCmdOrders, kCmdKeyChange, kCmdNewAccount, kCmdNewNonce,
    kCmdNewOrder, kCmdRenewalInfo, kCmdRevokeCert, kCmdNewAuthz,
    kCmdFinalize, kCmdCertificate, kCmdAuthorization, kCmdChallenge,
    kCmdDeactivate, kCmdUpdateAccount
};

ACMEClientDlg::ACMEClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));
    memset( &csr_pri_key_, 0x00, sizeof(BIN));
    memset( &kid_pub_key_, 0x00, sizeof(BIN));

    connect( mCmdTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCmdTableMenuRequested(QPoint)));
    connect( mAuthTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotAuthTableMenuRequested(QPoint)));
    connect( mChallTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotChallTableMenuRequested(QPoint)));
    connect( mOrderTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotOrderTableMenuRequested(QPoint)));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mKIDGetPubBtn, SIGNAL(clicked()), this, SLOT(clickKIDGetPubKey()));
    connect( mGetNonceBtn, SIGNAL(clicked()), this, SLOT(clickGetNonce()));
    connect( mGetLocationBtn, SIGNAL(clicked()), this, SLOT(clickGetLocation()));
    connect( mGetDirBtn, SIGNAL(clicked()), this, SLOT(clickGetDirectory()));
    connect( mChallTestBtn, SIGNAL(clicked()), this, SLOT(clickChallTest()));

    connect( mDNSCheckBtn, SIGNAL(clicked()), this, SLOT(clickDNSCheck()));

    connect( mCmdClearBtn, SIGNAL(clicked()), this, SLOT(clickClearCmd()));
    connect( mAuthClearBtn, SIGNAL(clicked()), this, SLOT(clickClearAuth()));
    connect( mChallClearBtn, SIGNAL(clicked()), this, SLOT(clickClearChall()));
    connect( mOrderClearBtn, SIGNAL(clicked()), this, SLOT(clickClearOrder()));

    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mThumbPrintBtn, SIGNAL(clicked()), this, SLOT(clickThumbPrint()));
    connect( mDeactivateBtn, SIGNAL(clicked()), this, SLOT(clickDeactivate()));
    connect( mUpdateAccountBtn, SIGNAL(clicked()), this, SLOT(clickUpdateAccount()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mClearRequestBtn, SIGNAL(clicked()), this, SLOT(clickClearRequest()));
    connect( mClearResponseBtn, SIGNAL(clicked()), this, SLOT(clickClearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));
    connect( mParserBtn, SIGNAL(clicked()), this, SLOT(clickParse()));
    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmd(int)));
    connect( mDNSAddBtn, SIGNAL(clicked()), this, SLOT(clickAddDNS()));
    connect( mDNSClearBtn, SIGNAL(clicked()), this, SLOT(clickClearDNS()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));
    connect( mRequestViewBtn, SIGNAL(clicked()), this, SLOT(clickRequestView()));
    connect( mResponseViewBtn, SIGNAL(clicked()), this, SLOT(clickResponseView()));
    connect( mIssueCertBtn, SIGNAL(clicked()), this, SLOT(clickIssueCert()));
    connect( mTestBtn, SIGNAL(clicked()), this, SLOT(clickTest()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mClearRequestBtn->setFixedWidth(34);
    mClearResponseBtn->setFixedWidth(34);

    mLinkTab->layout()->setSpacing(5);
    mLinkTab->layout()->setMargin(5);
    mUserTab->layout()->setSpacing(5);
    mUserTab->layout()->setMargin(5);
    mCmdTab->layout()->setSpacing(5);
    mCmdTab->layout()->setMargin(5);
    mAuthTab->layout()->setSpacing(5);
    mAuthTab->layout()->setMargin(5);
    mChallTab->layout()->setSpacing(5);
    mChallTab->layout()->setMargin(5);
    mOrderTab->layout()->setSpacing(5);
    mOrderTab->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
    mMakeBtn->setDefault(true);
}

ACMEClientDlg::~ACMEClientDlg()
{
    resetKey();
}

void ACMEClientDlg::initUI()
{
    mMethodCombo->addItems( kMethodList );
    mHashCombo->addItems( kHashList );

    mAutoNonceCheck->setChecked(true);
    mAutoSendCheck->setChecked(true);
    mAutoParseCheck->setChecked(true);

    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );
    mURLCombo->setFocus();

    mEmailText->setPlaceholderText( tr( "Email address" ));
    mDNSText->setPlaceholderText( tr( "Domain name system" ));

#if defined(QT_DEBUG)
    mEmailText->setText( "jykim74@gmail.com" );
    mDNSText->setText( "example.com" );

    mTestBtn->show();
#else
    mTestBtn->hide();
#endif

    mRspCmdText->setPlaceholderText( tr( "Command" ));
    mRequestText->setPlaceholderText( tr("JSON String" ));
    mResponseText->setPlaceholderText( tr("JSON or Base64 value") );

    QStringList sBaseLabels = { tr("Command"), tr( "URL" ) };

    mCmdTable->clear();
    mCmdTable->horizontalHeader()->setStretchLastSection(true);
    mCmdTable->setColumnCount(sBaseLabels.size());
    mCmdTable->setHorizontalHeaderLabels( sBaseLabels );
    mCmdTable->verticalHeader()->setVisible(false);
    mCmdTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCmdTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCmdTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCmdTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mCmdTable->setColumnWidth( 0, 120 );

    QStringList sLabels = { tr( "URL" ) };

    mAuthTable->clear();
    mAuthTable->horizontalHeader()->setStretchLastSection(true);
    mAuthTable->setColumnCount(sLabels.size());
    mAuthTable->setHorizontalHeaderLabels( sLabels );
    mAuthTable->verticalHeader()->setVisible(false);
    mAuthTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mAuthTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mAuthTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mAuthTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sChallLabels = { tr( "Type" ), tr( "URL" ) };

    mChallTable->clear();
    mChallTable->horizontalHeader()->setStretchLastSection(true);
    mChallTable->setColumnCount(sChallLabels.size());
    mChallTable->setHorizontalHeaderLabels( sChallLabels );
    mChallTable->verticalHeader()->setVisible(false);
    mChallTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mChallTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mChallTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mChallTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mOrderTable->clear();
    mOrderTable->horizontalHeader()->setStretchLastSection(true);
    mOrderTable->setColumnCount(sLabels.size());
    mOrderTable->setHorizontalHeaderLabels( sLabels );
    mOrderTable->verticalHeader()->setVisible(false);
    mOrderTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mOrderTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mOrderTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mOrderTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mInfoTab->setCurrentIndex(0);
}

void ACMEClientDlg::initialize()
{
    mUseCertManCheck->setChecked( berApplet->settingsMgr()->useCertMan() );
}

QStringList ACMEClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kACMEUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void ACMEClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kACMEUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kACMEUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

void ACMEClientDlg::resetKey()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
    JS_BIN_reset( &csr_pri_key_ );
    JS_BIN_reset( &kid_pub_key_ );
    key_name_.clear();
    mKeyNameLabel->setText( key_name_ );

    mKIDGetPubBtn->setStyleSheet( "" );
}

bool ACMEClientDlg::isCmd( const QString strName )
{
    for( int i = 0; i < kCmdList.size(); i++ )
    {
        QString strCmd = kCmdList.at(i);

        if( strCmd.toUpper() == strName.toUpper() )
            return true;
    }

    return false;
}

void ACMEClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kACMEUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void ACMEClientDlg::clickKIDGetPubKey()
{
    int ret = 0;
    BIN binReq = {0,0};
    int nStatus = 0;

    BIN binPub = {0,0};

    QString strKID = mKIDText->text();
    QString strURL;
    QString strRsp;
    QJsonObject objRsp;

    PriKeyInfoDlg priKeyInfo;

    if( strKID.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no KID" ), this );
        mKIDText->setFocus();
        return;
    }

    mCmdCombo->setCurrentText( kCmdAccount );
    strURL = mCmdText->text();
    if( strURL != strKID )
    {
        berApplet->warningBox( tr( "KID and Account URL are different" ), this );
        mKIDText->setFocus();
        return;
    }

    ret = clickMake();
    if( ret != 0 ) goto end;

    ret = clickSend();
    if( ret != 0 ) goto end;

    strRsp = mResponseText->toPlainText();

    objRsp = QJsonDocument::fromJson( strRsp.toLocal8Bit() ).object();
    ret = ACMEObject::getPubKey( objRsp["key"].toObject(), &binPub );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "failed to get the public key from response: %1").arg(ret), this );
        goto end;
    }

    JS_BIN_reset( &kid_pub_key_ );
    JS_BIN_copy( &kid_pub_key_, &binPub );

    priKeyInfo.setPublicKey( &binPub );
    priKeyInfo.exec();

    mKIDGetPubBtn->setStyleSheet( "background-color: #CCFFEE;" );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binPub );
}

void ACMEClientDlg::clickClearRequest()
{
    mRequestText->clear();
}

void ACMEClientDlg::clickClearResponse()
{
    mResponseText->clear();
}

void ACMEClientDlg::changeRequest()
{
    QString strReq = mRequestText->toPlainText();
    QString strLen = getDataLenString( DATA_STRING, strReq );
    mRequestLenText->setText( strLen );
}

void ACMEClientDlg::changeResponse()
{
    QString strRsp = mResponseText->toPlainText();
    QString strLen = getDataLenString( DATA_STRING, strRsp );
    mResponseLenText->setText( strLen );
}

int ACMEClientDlg::parseGetDirectory( QJsonObject& object )
{
    QStringList listKeys;

    listKeys = object.keys();

    mCmdCombo->clear();
    mCmdCombo->addItem( "" );
    mCmdCombo->addItem( kCmdLocation );

    for( int i = 0; i < listKeys.size(); i++ )
    {
        QString strCmd = listKeys.at(i);
        berApplet->log( QString( "Key: %1").arg( listKeys.at(i)));
        QString strValue = object[strCmd].toString();
        berApplet->log( QString( "Value: %1" ).arg( strValue ));

        if( strCmd.toUpper() == kCmdNewNonce.toUpper() )
            mNonceURLText->setText( strValue );

        if( strCmd.toLower() != "meta" )
            addCmd( strCmd, strValue );
    }

    return 0;
}

int ACMEClientDlg::parseNewAccountRsp( QJsonObject& object )
{
    int ret = 0;
    QString strOrders = object["orders"].toString();

    if( strOrders.length() > 0 )
    {
        ret = addCmd( kCmdOrders, strOrders );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdOrders ).arg( strOrders ), this);
        }
    }

    return 0;
}

int ACMEClientDlg::parseCertificateRsp( const QString strChain )
{
    int ret = -1;
    BINList *pBinList = NULL;
    BINList *pCurList = NULL;

    int nCount = 0;

    /*
    QString strURL = mCmdText->text();
    QUrl url( strURL );
    QString strPath = url.path();
    QStringList listPath = strPath.split( "/" );

    if( listPath.size() > 0 )
    {
        QString strCertID = listPath.at( listPath.size() - 1 );
        mCertIDText->setText( strCertID );
    }
    */

    nCount = JS_BIN_decodePEMList( strChain.toStdString().c_str(), &pBinList );
    if( nCount <= 0 ) goto end;

    ret = savePriKeyCert( &csr_pri_key_, &pBinList->Bin );

    pCurList = pBinList;

    while( pCurList )
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &pCurList->Bin );
        certInfo.exec();

        pCurList = pCurList->pNext;
    }

end :
    if( pBinList ) JS_BIN_resetList( &pBinList );

    return ret;
}

int ACMEClientDlg::parseNewOrderRsp( QJsonObject& object )
{
    int ret = 0;
    QJsonArray jArr = object["authorizations"].toArray();
    QString strFinalValue = object["finalize"].toString();

    if( strFinalValue.length() > 0 )
    {
        ret = addCmd( kCmdFinalize, strFinalValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdFinalize ).arg( strFinalValue ), this);
        }
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QString strValue = jArr.at(i).toString();

        ret = addCmd( kCmdAuthorization, strValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdAuthorization ).arg( strValue ), this);
        }
    }

    return 0;
}

int ACMEClientDlg::parseOrdersRsp( QJsonObject& object )
{
    int ret = 0;
    QJsonValue jValue = object["orders"];

    if( jValue.isArray() )
    {
        QJsonArray jArr = object["orders"].toArray();
        for( int i = 0; i < jArr.size(); i++ )
        {
            QString strValue = jArr.at(i).toString();
            ret = addCmd( kCmdOrder, strValue );
            if( ret > 0 )
            {
                berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdOrder ).arg( strValue ), this);
            }
        }
    }
    else if( jValue.isString() )
    {
        QString strValue = jValue.toString();
        ret = addCmd( kCmdOrder, strValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdOrder ).arg( strValue ), this);
        }
    }

    return 0;
}

int ACMEClientDlg::parseOrderRsp( QJsonObject& object )
{
    int ret = 0;
    QJsonArray jArr = object["authorizations"].toArray();
    QString strFinalValue = object["finalize"].toString();

    if( strFinalValue.length() > 0 )
    {
        ret = addCmd( kCmdFinalize, strFinalValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdFinalize ).arg( strFinalValue ), this);
        }
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QString strValue = jArr.at(i).toString();

        ret = addCmd( kCmdAuthorization, strValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdAuthorization ).arg( strValue ), this);
        }
    }

    QString strCert = object["certificate"].toString();

    if( strCert.length() > 1 )
    {
        ret = addCmd( kCmdCertificate, strCert );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdCertificate ).arg( strCert ), this);
        }
    }

    return 0;
}

int ACMEClientDlg::parseAuthzRsp( QJsonObject& object )
{
    int ret = 0;

    QString strStatus = object["status"].toString();
    QJsonArray jArr = object["challenges"].toArray();

    for( int i = 0; i < jArr.count(); i++ )
    {
        QJsonObject jObj = jArr.at(i).toObject();
        QString strType = jObj["type"].toString();
        QString strURL = jObj["url"].toString();
        QString strToken = jObj["token"].toString();
        QString strStatus = jObj["status"].toString();

        ret = addCmd( kCmdChallenge, strURL );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdChallenge ).arg( strURL ), this);

            mChallTable->insertRow(0);
            mChallTable->setRowHeight(0,10);
            mChallTable->setItem(0, 0, new QTableWidgetItem( strType ));
            mChallTable->setItem(0, 1, new QTableWidgetItem( strURL ));
        }
    }

    return 0;
}

int ACMEClientDlg::parseLocationRsp( QJsonObject& object )
{
    int ret = 0;
    QJsonArray jArr = object["authorizations"].toArray();
    QString strFinalValue = object["finalize"].toString();

    if( strFinalValue.length() > 0 )
    {
        ret = addCmd( kCmdFinalize, strFinalValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdFinalize ).arg( strFinalValue ), this);
        }
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QString strValue = jArr.at(i).toString();

        ret = addCmd( kCmdAuthorization, strValue );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdAuthorization ).arg( strValue ), this);
        }
    }

    QString strCert = object["certificate"].toString();

    if( strCert.length() > 1 )
    {
        ret = addCmd( kCmdCertificate, strCert );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdCertificate ).arg( strCert ), this);
        }
    }

    return 0;
}

int ACMEClientDlg::parseAccountRsp( QJsonObject& object )
{
    int ret = -1;

    QString strOrders = object["orders"].toString();

    if( strOrders.length() > 0 )
    {
        ret = addCmd( kCmdOrders, strOrders );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdOrders ).arg( strOrders ), this);
        }

        ret = 0;
    }

    QString strCert = object["certificate"].toString();

    if( strCert.length() > 0 )
    {
        ret = addCmd( kCmdCertificate, strCert );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Added %1 command [%2]" ).arg( kCmdCertificate ).arg( strCert ), this);
        }

        QUrl url( strCert );
        QString strPath = url.path();
        QStringList listPath = strPath.split( "/" );

        if( listPath.size() > 0 )
        {
            QString strCertID = listPath.at( listPath.size() - 1 );

            bool bVal = berApplet->yesOrNoBox( tr( "Change Cert ID as %1?" ).arg( strCertID ), this, true );
            if( bVal == true )
                mCertIDText->setText( strCertID );
        }

        ret = 0;
    }

    return ret;
}

int ACMEClientDlg::addCmd( const QString strCmd, const QString strCmdURL )
{
    for( int i = 0; i < mCmdCombo->count(); i++ )
    {
        QString strItemURL = mCmdCombo->itemData(i).toString();

        if( strItemURL.compare( strCmdURL, Qt::CaseInsensitive ) == 0 )
            return 0;
    }

    mCmdCombo->addItem( strCmd.toUpper(), strCmdURL );

    if( strCmd == kCmdAuthorization )
    {
        mAuthTable->insertRow(0);
        mAuthTable->setRowHeight(0,10);
        mAuthTable->setItem(0, 0, new QTableWidgetItem( strCmdURL ));
    }
    else if( strCmd == kCmdOrder )
    {
        mOrderTable->insertRow(0);
        mOrderTable->setRowHeight(0,10);
        mOrderTable->setItem(0, 0, new QTableWidgetItem( strCmdURL ));
    }

    berApplet->log( QString( "Add command [%1 : %2]").arg( strCmd.toUpper() ).arg( strCmdURL ));
    return 1;
}

int ACMEClientDlg::clickParse()
{
    int ret = 0;
    update();

    QString strRsp = mResponseText->toPlainText();
    QString strCmd = mRspCmdText->text();
    int nStatus = mStatusText->text().toInt();

    if( strRsp.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response"), this );
        mResponseText->setFocus();
        return -1;
    }

    QJsonDocument jsonDoc;
    jsonDoc = QJsonDocument::fromJson( strRsp.toLocal8Bit() );
    berApplet->log( jsonDoc.toJson() );
    QJsonObject object = jsonDoc.object();

    if( object["status"].isString() == false )
    {
        nStatus = object["status"].toInt();
        if( nStatus >= 300 )
        {
            QString strDetail = object["detail"].toString();
            berApplet->warningBox( tr("Error: %1 status: %2").arg( strDetail) .arg( nStatus ), this);
            return -1;
        }
    }

    if( strCmd.toUpper() == kCmdCertificate.toUpper() )
    {
        mRspStatusText->setText( tr("Done") );
        ret = parseCertificateRsp( strRsp );
    }
    else
    {
        QString strStatus = object["status"].toString();
        mRspStatusText->setText( strStatus );
        nStatus = strStatus.toInt();

        if( nStatus >= 300 )
        {
            QString strDetail = object["detail"].toString();
            berApplet->warningBox( tr("Error: %1 status: %2").arg( strDetail) .arg( nStatus ), this);
            return -1;
        }

        if( strCmd.toUpper() == kCmdDirectory.toUpper() )
        {
            ret = parseGetDirectory( object );
        }
        else if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
        {
            ret = parseNewOrderRsp( object );
        }
        else if( strCmd.toUpper() == kCmdAuthorization.toUpper() )
        {
            ret = parseAuthzRsp( object );
        }
        else if( strCmd.toUpper() == kCmdAccount.toUpper() )
        {
            ret = parseAccountRsp( object );
        }
        else if( strCmd.toUpper() == kCmdOrders.toUpper() )
        {
            ret = parseOrdersRsp( object );
        }
        else if( strCmd.toUpper() == kCmdOrder.toUpper() )
        {
            ret = parseOrderRsp( object );
        }
        else if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
        {
            ret = parseNewAccountRsp( object );
        }
        else if( strCmd.toUpper() == kCmdLocation.toUpper() )
        {
            ret = parseLocationRsp( object );
        }
    }

    if( ret == 0 )
        berApplet->messageBox( tr( "%1 Parsing completed" ).arg( strCmd ), this );
    else
        berApplet->warningBox( tr( "%1 failed to parse : %2").arg( strCmd ).arg( ret ), this );

    return ret;
}

void ACMEClientDlg::changeCmd( int index )
{
    QString strCmd = mCmdCombo->currentText();
    if( strCmd == kCmdLocation)
    {
        mCmdText->setText( mLocationText->text() );
    }
    else
    {
        QString strURL = mCmdCombo->currentData().toString();
        mCmdText->setText( strURL );
    }
}

void ACMEClientDlg::clickAddDNS()
{
    int i = 0;

    QString strDNS = mDNSText->text();

    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS name" ), this );
        mDNSText->setFocus();
        return;
    }

    for( i = 0; i < mDNSList->count(); i++ )
    {
        QString strLine = mDNSList->item(i)->text();

        if( strLine == strDNS )
        {
            berApplet->warningBox( tr("%1 already exists" ).arg( strDNS ), this );
            return;
        }
    }

    mDNSList->insertItem( 0, strDNS );
    mDNSText->clear();
}

void ACMEClientDlg::clickClearDNS()
{
    mDNSList->clear();
}

void ACMEClientDlg::clickClearAll()
{
    mNonceText->clear();
    mNonceURLText->clear();
    mDNSText->clear();
    mDNSList->clear();
    mCmdCombo->clear();
    mCmdText->clear();
    mRequestText->clear();
    mResponseText->clear();
    mRspCmdText->clear();
    mLocationText->clear();
    mKIDText->clear();
    mStatusText->clear();

    clickClearCmd();
    clickClearAuth();
    clickClearChall();
    clickClearOrder();

    resetKey();
}

void ACMEClientDlg::clickVerify()
{
    BIN binPub = {0,0};
    QString strRequest = mRequestText->toPlainText();

    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr("No request available" ), this );
        return;
    }

    ACMEObject acmeObj;
    acmeObj.setObjectFromJson( strRequest );
    QJsonObject objProtected = acmeObj.getProtected();

    if( objProtected["jwk"].isObject() == true )
    {
        JS_BIN_reset( &kid_pub_key_ );
        ACMEObject::getPubKey( objProtected["jwk"].toObject(), &kid_pub_key_ );
    }

    if( kid_pub_key_.nLen <= 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            CertManDlg certMan;

            certMan.setMode( ManModeSelCert );
            certMan.setTitle( tr( "Select a sign certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return;

            certMan.getCert( &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, &binPub );
            JS_BIN_reset( &binCert );
        }
        else
        {
            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return;

            QString strPubPath = keyPairMan.getPubPath();

            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
        }
    }
    else
    {
        JS_BIN_copy( &binPub, &kid_pub_key_ );
    }


    int ret = acmeObj.verifySignature( &binPub );
    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr("Verify fail: %1").arg( ret ), this );

    JS_BIN_reset( &binPub );
}

void ACMEClientDlg::clickRequestView()
{
    QString strRequest = mRequestText->toPlainText();
    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr( "No request available" ), this );
        return;
    }

    JSONTreeDlg jsonTree(nullptr);
    jsonTree.setJson( strRequest );
    jsonTree.exec();
}

void ACMEClientDlg::clickResponseView()
{
    QString strResponse = mResponseText->toPlainText();
    if( strResponse.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response" ), this );
        return;
    }

    QString strRspCmd = mRspCmdText->text();

    if( strRspCmd.toUpper() == kCmdCertificate )
    {
        BINList *pBinList = NULL;
        BINList *pCurList = NULL;
        int nCount = JS_BIN_decodePEMList( strResponse.toStdString().c_str(), &pBinList );

        if( nCount <= 0 ) return;

        pCurList = pBinList;
        while( pCurList )
        {
            CertInfoDlg certInfo;
            certInfo.setCertBIN( &pBinList->Bin );
            certInfo.exec();

            pCurList = pCurList->pNext;
        }

        if( pBinList ) JS_BIN_resetList( &pBinList );
    }
    else
    {
        JSONTreeDlg jsonTree(nullptr);
        jsonTree.setJson( strResponse );
        jsonTree.exec();
    }
}

void ACMEClientDlg::slotCmdTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *remakeCmdAct = new QAction( tr( "Remake Cmd" ), this );
    QAction *deleteCmdAct = new QAction( tr( "Delete Cmd" ), this );


    connect( deleteCmdAct, SIGNAL(triggered()), this, SLOT(deleteCmd()));
    connect( remakeCmdAct, SIGNAL(triggered()), this, SLOT(remakeCmd()));

    menu->addAction( deleteCmdAct );
    menu->addAction( remakeCmdAct );

    menu->popup( mCmdTable->viewport()->mapToGlobal(pos));
}

void ACMEClientDlg::slotAuthTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *remakeAuthAct = new QAction( tr( "Remake Auth" ), this );
    QAction *deleteAuthAct = new QAction( tr( "Delete Auth" ), this );


    connect( deleteAuthAct, SIGNAL(triggered()), this, SLOT(deleteAuth()));
    connect( remakeAuthAct, SIGNAL(triggered()), this, SLOT(remakeAuth()));

    menu->addAction( deleteAuthAct );
    menu->addAction( remakeAuthAct );

    menu->popup( mAuthTable->viewport()->mapToGlobal(pos));
}

void ACMEClientDlg::slotChallTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *remakeChallAct = new QAction( tr( "Remake Challenge" ), this );
    QAction *deleteChallAct = new QAction( tr( "Delete Challenge" ), this );


    connect( deleteChallAct, SIGNAL(triggered()), this, SLOT(deleteChall()));
    connect( remakeChallAct, SIGNAL(triggered()), this, SLOT(remakeChall()));

    menu->addAction( deleteChallAct );
    menu->addAction( remakeChallAct );

    menu->popup( mChallTable->viewport()->mapToGlobal(pos));
}

void ACMEClientDlg::slotOrderTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *remakeAct = new QAction( tr( "Remake Order" ), this );
    QAction *deleteAct = new QAction( tr( "Delete Order" ), this );


    connect( deleteAct, SIGNAL(triggered()), this, SLOT(deleteOrder()));
    connect( remakeAct, SIGNAL(triggered()), this, SLOT(remakeOrder()));

    menu->addAction( deleteAct );
    menu->addAction( remakeAct );

    menu->popup( mOrderTable->viewport()->mapToGlobal(pos));
}

void ACMEClientDlg::deleteCmd()
{
    QModelIndex idx = mCmdTable->currentIndex();
    QTableWidgetItem *item = mCmdTable->item(idx.row(), 0);
    if( item == NULL ) return;
    mCmdTable->removeRow(idx.row());
}

void ACMEClientDlg::remakeCmd()
{
    QModelIndex idx = mCmdTable->currentIndex();
    QTableWidgetItem *item = mCmdTable->item(idx.row(), 0);
    QTableWidgetItem *item1 = mCmdTable->item(idx.row(), 1);
    if( item == NULL || item1 == NULL ) return;

    QString strCmd = item->text();
    QString strURL = item1->text();

    makeCmd( strCmd, strURL );
}

void ACMEClientDlg::deleteAuth()
{
    QModelIndex idx = mAuthTable->currentIndex();
    QTableWidgetItem *item = mAuthTable->item(idx.row(), 0);
    if( item == NULL ) return;
    mAuthTable->removeRow(idx.row());
}

void ACMEClientDlg::remakeAuth()
{
    QModelIndex idx = mAuthTable->currentIndex();
    QTableWidgetItem *item = mAuthTable->item(idx.row(), 0);

    if( item == NULL ) return;

    QString strURL = item->text();

    makeCmd( kCmdAuthorization, strURL );
}

void ACMEClientDlg::deleteChall()
{
    QModelIndex idx = mChallTable->currentIndex();
    QTableWidgetItem *item = mChallTable->item(idx.row(), 0);
    if( item == NULL ) return;
    mChallTable->removeRow(idx.row());
}

void ACMEClientDlg::remakeChall()
{
    QModelIndex idx = mChallTable->currentIndex();
    QTableWidgetItem *item = mChallTable->item(idx.row(), 1);
    if( item == NULL ) return;

    QString strURL = item->text();

    makeCmd( kCmdChallenge, strURL );
}

void ACMEClientDlg::deleteOrder()
{
    QModelIndex idx = mOrderTable->currentIndex();
    QTableWidgetItem *item = mOrderTable->item(idx.row(), 0);
    if( item == NULL ) return;
    mOrderTable->removeRow(idx.row());
}

void ACMEClientDlg::remakeOrder()
{
    QModelIndex idx = mOrderTable->currentIndex();
    QTableWidgetItem *item = mOrderTable->item(idx.row(), 0);

    if( item == NULL ) return;

    QString strURL = item->text();

    makeCmd( kCmdOrder, strURL );
}

void ACMEClientDlg::clickGetNonce()
{
    int nStatus = 0;
    const char *pHeaderName = "Replay-Nonce";
    QString strURL = mNonceURLText->text();
    char *pNonce = NULL;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a Nonce URL" ), this );
        mNonceURLText->setFocus();
        return;
    }

    JS_HTTP_requestGetRspHeaderValue(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        &nStatus,
        pHeaderName, &pNonce );

    if( nStatus >= 300 )
    {
        berApplet->warningBox( tr( "failed to retrieve nonce: %1").arg( nStatus ), this );
        return;
    }

    if( pNonce )
    {
        mNonceText->setText( pNonce );
        JS_free( pNonce );
        berApplet->messageBox( tr( "Nonce fetch success" ), this );
    }

}

void ACMEClientDlg::clickGetLocation()
{
    int ret = 0;
    int nStatus = 0;
    BIN binRsp = {0,0};

    QString strLocation = mLocationText->text();

    if( strLocation.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no location URL"), this );
        mLocationText->setFocus();
        return;
    }

    ret = JS_HTTP_requestGetBin2( strLocation.toStdString().c_str(), NULL, NULL, &nStatus, &binRsp );

    if( ret == 0 )
    {
        QString strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
        mRspCmdText->setText( mCmdCombo->currentText() );
        berApplet->log( QString( "Response: %1").arg( strRsp ));

        mRspCmdText->setText( kCmdLocation );
        mRspStatusText->setText( QString("%1").arg( nStatus ));
        berApplet->messageBox( tr("Location retrieved successfully"), this );
    }
    else
    {
        berApplet->warnLog( tr( "failed to send a request to the ACME server: %1").arg( ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binRsp );
}

void ACMEClientDlg::clickGetDirectory()
{
    int ret = 0;
    int nStatus = 0;
    BIN binRsp = {0,0};
    QJsonDocument   jDoc;
    QJsonObject     jObj;
    QString strRsp;
    QStringList listKeys;

    QString strURL = mURLCombo->currentText();

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert ACME URL"), this );
        goto end;
    }

    ret = JS_HTTP_requestGetBin2( strURL.toStdString().c_str(), NULL, NULL, &nStatus, &binRsp );

    if( ret == 0 )
    {
        strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
        setUsedURL( strURL );
    }
    else
    {
        berApplet->warnLog( tr( "failed to send a request to the ACME server: %1").arg( ret), this );
        goto end;
    }

    jDoc = QJsonDocument::fromJson( strRsp.toLocal8Bit() );
    jObj = jDoc.object();

    listKeys = jObj.keys();
    mCmdCombo->clear();
    mCmdCombo->addItem( "" );
    mCmdCombo->addItem( kCmdLocation );

    for( int i = 0; i < listKeys.size(); i++ )
    {
        QString strCmd = listKeys.at(i);
        berApplet->log( QString( "Key: %1").arg( listKeys.at(i)));
        QString strValue = jObj[strCmd].toString();
        berApplet->log( QString( "Value: %1" ).arg( strValue ));

        if( strCmd.toUpper() == kCmdNewNonce.toUpper() )
            mNonceURLText->setText( strValue );

        if( isCmd( strCmd ) == true )
            addCmd( strCmd, strValue );
    }

    mCmdCombo->setCurrentText( kCmdLocation );

    mRspCmdText->setText( kCmdDirectory  );
    mStatusText->setText( QString("%1").arg( nStatus ));
    berApplet->messageBox( tr("Successfully retrieved directory message"), this );

end :
    JS_BIN_reset( &binRsp );
}

void ACMEClientDlg::clickChallTest()
{
    QString strHost = mDNSText->text();

    ChallTestDlg challTest;
//    challTest.mHostText->setText( strHost );
    challTest.exec();
}

void ACMEClientDlg::clickDNSCheck()
{
    DNSCheckDlg dnsCheck;

    if( pub_key_.nLen > 0 )
    {
        dnsCheck.setPubKey( &pub_key_ );
    }

    int nCount = mDNSList->count();
    for( int i = 0; i < nCount; i++ )
    {
        QListWidgetItem *item = mDNSList->item(i);
        dnsCheck.addDNS( item->text() );
    }

    dnsCheck.exec();
}

void ACMEClientDlg::clickClearCmd()
{
    mCmdTable->setRowCount(0);
}

void ACMEClientDlg::clickClearAuth()
{
    mAuthTable->setRowCount(0);
}

void ACMEClientDlg::clickClearChall()
{
    mChallTable->setRowCount(0);
}

void ACMEClientDlg::clickClearOrder()
{
    mOrderTable->setRowCount(0);
}

int ACMEClientDlg::makeKeyExchange( QJsonObject& object )
{
    BIN binPub = {0,0};
    BIN binPri = {0,0};

    QString strName;
    QString strPubPath;
    QString strPriPath;

    int nKeyType = -1;
    QString strHash = mHashCombo->currentText();
    QString strNonce = mNonceText->text();
    QString strAlg;
    QString strURL = mCmdText->text();
    QString strAccount = mKIDText->text();

    ACMEObject acmeObj;
    QJsonObject objNewJWK;
    QJsonObject objOldJWK;
    QJsonObject objPayload;
    QJsonObject objProtected;

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a new certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return -1;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
        JS_PKI_getPubKeyFromCert( &binCert, &binPub );
        JS_BIN_reset( &binCert );
        strName = certMan.getSeletedCertPath();
    }
    else
    {
        KeyPairManDlg keyPairMan;
        keyPairMan.setTitle( tr( "Select new keypair" ));
        keyPairMan.setMode( KeyPairModeSelect );

        if( keyPairMan.exec() != QDialog::Accepted )
            return -1;

        strPubPath = keyPairMan.getPubPath();
        strPriPath = keyPairMan.getPriPath();
        strName = keyPairMan.getName();

        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
        JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
    }

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_EDDSA )
    {
        berApplet->warningBox(
            tr( "Only RSA ECDSA EDDSA algorithms are supported [Current key algorithm %1]")
                .arg( JS_PKI_getKeyAlgName( nKeyType)),  this );
        goto end;
    }

    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objNewJWK = ACMEObject::getJWK( &binPub, strHash, strName );
    objOldJWK = ACMEObject::getJWK( &pub_key_, strHash, key_name_ );
    objProtected = acmeObj.getJWKProtected( strAlg, objNewJWK, "", strURL );

    objPayload["account"] = strAccount;
    objPayload["oldKey"] = objOldJWK;

    acmeObj.setProtected( objProtected );
    acmeObj.setPayload( objPayload );
    acmeObj.setSignature( &binPri, strHash );

    object = acmeObj.getObject();

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );

    return 0;
}

int ACMEClientDlg::makeNewAccount( QJsonObject& object )
{
    QString strEmail = mEmailText->text();
    bool bTermsOfServiceAgreed = true;
    QString strStatus = "valid";
    QString strOrders;

    QStringList listEmail;

    OneListDlg oneList;
    oneList.setName( "Email" );
    if( strEmail.length() > 0 ) oneList.addName( strEmail );

    if( oneList.exec() != QDialog::Accepted )
        return -1;

    listEmail = oneList.getList();

    object = ACMEObject::getNewAccountPayload( strStatus, listEmail, bTermsOfServiceAgreed, strOrders );

    return 0;
}

int ACMEClientDlg::makeNewNonce( QJsonObject& object )
{
    clickGetNonce();
    return 0;
}

int ACMEClientDlg::makeNewOrder( QJsonObject& object )
{
    QString strDNS = mDNSText->text();
    QStringList strDNSList;

    if( mDNSList->count() < 1 )
    {
        berApplet->warningBox( tr( "There is no DNS" ), this );
        mDNSText->setFocus();
        return -1;
    }

    for( int i = 0; i < mDNSList->count(); i++ )
    {
        QString strValue = mDNSList->item(i)->text();
        strDNSList.append( strValue );
    }

    object = ACMEObject::getIdentifiers( strDNSList );
    return 0;
}

int ACMEClientDlg::makeRevokeCert( QJsonObject& object )
{
    BIN binCert = {0,0};
    char *pValue;

    int nReason = -1;

    RevokeReasonDlg revokeReason;
    if( revokeReason.exec() != QDialog::Accepted )
        return -1;

    nReason = revokeReason.mReasonText->text().toInt();

    CertManDlg certMan;
    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getCert( &binCert );
    JS_BIN_encodeBase64URL( &binCert, &pValue );

    object["reason"] = nReason;
    object["certificate"] = pValue;

    JS_BIN_reset( &binCert );
    if( pValue ) JS_free( pValue );

    return 0;
}

int ACMEClientDlg::makeFinalize( QJsonObject& object )
{
    int ret = 0;
    QString strHex;
    QStringList listSAN;

    BIN binCSR = {0,0};

    MakeCSRDlg makeCSR;
    CSRInfoDlg csrInfo;

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair for CSR" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return -1;

    QString strPriPath = keyPairMan.getPriPath();

    JS_BIN_reset( &csr_pri_key_ );
    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &csr_pri_key_ );


    makeCSR.setInfo( tr( "Make CSR" ) );
    makeCSR.setPriKey( &csr_pri_key_ );

    for( int i = 0; i < mDNSList->count(); i++ )
    {
        QString strDNS = mDNSList->item(i)->text();
        if( i == 0 ) makeCSR.mCNText->setText( strDNS );

        listSAN.append( strDNS );
    }

    if( listSAN.size() > 0 ) makeCSR.setSAN( listSAN );

    if( makeCSR.exec() != QDialog::Accepted )
    {
        ret = -1;
        goto end;
    }


    strHex = makeCSR.getCSRHex();

    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binCSR );

    object["csr"] = getBase64URL_FromHex( strHex );
    ret = 0;

    if( berApplet->yesOrNoBox( tr( "Would you like to save this CSR?" ), this ) == true )
    {
        ExportDlg exportDlg;
        exportDlg.setCSR( &binCSR );
        exportDlg.setName( makeCSR.getDN() );
        exportDlg.exec();
    }

end :
    JS_BIN_reset( &binCSR );

    return ret;
}

int ACMEClientDlg::makeRenewalInfo( QJsonObject& object )
{
    int ret = 0;
    QString strCertID = mCertIDText->text();

    if( strCertID.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a certificate ID" ), this );
        mCertIDText->setFocus();
        return -1;
    }

    object["certID"] = "certificate ID";
    object["replaced"] = true;

    return 0;
}

int ACMEClientDlg::makeDeactivate( QJsonObject& object )
{
    object["status"] = "deactivated";

    return 0;
}

int ACMEClientDlg::makeUpadateAccount( QJsonObject& object )
{
    QJsonArray jArr;
    QJsonValue jValue;
    QString strEmail = mEmailText->text();
    QStringList listEmail;

    OneListDlg oneList;
    oneList.setName( "Email" );
    if( strEmail.length() > 0 ) oneList.addName( strEmail );

    if( oneList.exec() != QDialog::Accepted )
        return -1;

    listEmail = oneList.getList();

    for( int i = 0; i < listEmail.size(); i++ )
    {
        jValue = QString( "mailto: %1").arg( listEmail.at(i) );
        jArr.append( jValue );
    }

    object["contact"] = jArr;

    return 0;
}

int ACMEClientDlg::clickMake()
{
    int ret = 0;

    QString strCmd = mCmdCombo->currentText();
    QString strURL = mCmdText->text();

    ret = makeCmd( strCmd, strURL );

    return ret;
}


int ACMEClientDlg::makeCmd( const QString strCmd, const QString strURL )
{
    int ret = 0;
    int nKeyType = -1;

    ACMEObject acmeObj;
//    QString strCmd = mCmdCombo->currentText();
//    QString strURL = mCmdText->text();

    QString strHash = mHashCombo->currentText();
    QString strKID = mKIDText->text();

    QString strJWK;
    QJsonObject objJWK;
    QJsonObject objPayload;
    QJsonObject objProtected;

    QString strNonce = mNonceText->text();
    QString strAlg;


    if( pri_key_.nLen <= 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            JCertInfo sCertInfo;
            CertManDlg certMan;

            memset( &sCertInfo, 0x00, sizeof(sCertInfo));

            certMan.setMode( ManModeSelBoth );
            certMan.setTitle( tr( "Select account certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return -1;

            certMan.getPriKey( &pri_key_ );
            certMan.getCert( &binCert );
            JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
            key_name_ = sCertInfo.pSubjectName;
            JS_PKI_getPubKeyFromCert( &binCert, &pub_key_ );
            JS_BIN_reset( &binCert );
            JS_PKI_resetCertInfo( &sCertInfo );
        }
        else
        {
            QString strPubPath;
            QString strPriPath;

            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select account keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return -1;

            strPubPath = keyPairMan.getPubPath();
            strPriPath = keyPairMan.getPriPath();
            key_name_ = keyPairMan.getName();

            JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &pri_key_ );
            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &pub_key_ );
        }

        mKeyNameLabel->setText( QString( " | KeyName: %1" ).arg( key_name_ ));
    }

    nKeyType = JS_PKI_getPriKeyType( &pri_key_ );
    if( nKeyType != JS_PKI_KEY_TYPE_RSA && nKeyType != JS_PKI_KEY_TYPE_ECDSA && nKeyType != JS_PKI_KEY_TYPE_EDDSA )
    {
        berApplet->warningBox(
            tr( "Only RSA ECDSA EDDSA algorithms are supported [Current key algorithm %1]")
                .arg( JS_PKI_getKeyAlgName( nKeyType)),  this );
        return JSR_INVALID_ALG;
    }

    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &pub_key_, strHash, key_name_ );

    if( strCmd.toUpper() == kCmdKeyChange.toUpper() )
    {
        ret = makeKeyExchange(objPayload);

        ACMEObject payObj;
        payObj.setObject( objPayload );
        acmeObj.setPayload( payObj.getPacketJson() );
    }
    else if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
    {
        ret = makeNewAccount(objPayload);
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdNewNonce.toUpper() )
    {
        ret = makeNewNonce(objPayload);
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
    {
        ret = makeNewOrder(objPayload);
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdRenewalInfo.toUpper() )
    {
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdRevokeCert.toUpper() )
    {
        ret = makeRevokeCert(objPayload);
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdFinalize.toUpper() )
    {
        ret = makeFinalize( objPayload );
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdRenewalInfo.toUpper() )
    {
        ret = makeRenewalInfo( objPayload );
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdDeactivate.toUpper() )
    {
        ret = makeDeactivate( objPayload );
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdUpdateAccount.toUpper() )
    {
        ret = makeUpadateAccount( objPayload );
        acmeObj.setPayload( objPayload );
    }
    else if( strCmd.toUpper() == kCmdChallenge.toUpper() )
    {
        acmeObj.setPayload( objPayload );
        ret = JSR_OK;
    }
    else
    {

    }

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to make payload: %1" ).arg( ret ), this );
        return ret;
    }

    update();
    berApplet->log( QString("Payload: %1").arg( acmeObj.getPayloadJSON() ));

    if( strKID.length() > 0 )
        objProtected = acmeObj.getKidProtected( strAlg, strKID, strNonce, strURL );
    else
        objProtected = acmeObj.getJWKProtected( strAlg, objJWK, strNonce, strURL );

    acmeObj.setProtected( objProtected );

    berApplet->log( QString("Protected: %1").arg( acmeObj.getProtectedJSON() ));

    ret = acmeObj.setSignature( &pri_key_, strHash );

    if( ret == JSR_OK )
    {
        mRequestText->setPlainText( acmeObj.getPacketJson() );
        berApplet->messageBox( tr("Successfully created message"), this );
    }

    mResponseText->clear();
    mRspCmdText->clear();
    mStatusText->clear();

    if( mAutoSendCheck->isChecked() == true )
        clickSend();

    return ret;
}

int ACMEClientDlg::clickDeactivate()
{
    for( int i = 0; i < mCmdCombo->count(); i++ )
    {
        QString strCmd = mCmdCombo->itemText(i);
        if( strCmd == kCmdDeactivate ) break;

        if( (i + 1) == mCmdCombo->count() )
            mCmdCombo->addItem( kCmdDeactivate, "" );
    }

    addCmd( kCmdDeactivate, "" );
    mCmdCombo->setCurrentText(kCmdDeactivate);

    return clickMake();
}

int ACMEClientDlg::clickUpdateAccount()
{
    for( int i = 0; i < mCmdCombo->count(); i++ )
    {
        QString strCmd = mCmdCombo->itemText(i);
        if( strCmd == kCmdUpdateAccount ) break;

        if( (i + 1) == mCmdCombo->count() )
            mCmdCombo->addItem( kCmdUpdateAccount, "" );
    }

    addCmd( kCmdUpdateAccount, "" );
    mCmdCombo->setCurrentText(kCmdUpdateAccount);

    return clickMake();
}

int ACMEClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strCmdURL = mCmdText->text();
    QString strRspCmd = mRspCmdText->text();
    QString strMethod = mMethodCombo->currentText();
    QString strKID = mKIDText->text();
    QString strCmdType = mCmdCombo->currentText();

    QString strLink;
    JNameValList *pRspHeaderList = NULL;
    JNameValList *pCurList = NULL;

    int nCount = mCmdCombo->count();
    QStringList listLink;
    for( int i = 0; i < nCount; i++ )
    {
        QString strType = mCmdCombo->itemText(i);

        if( strType == strCmdType )
        {
            strLink = mCmdCombo->itemData( i, Qt::UserRole ).toString();
            listLink.append( strLink );
        }
    }

    if( listLink.size() > 1 )
    {
        SelListDlg selList;
        selList.setHeadLabel( tr( "Select %1 URL" ).arg( strCmdType ));
        for( int i = 0; i < listLink.size(); i++ )
        {
            selList.addList( strCmdType, listLink.at(i));
        }

        selList.selectURL( strCmdURL );

        if( selList.exec() != QDialog::Accepted )
        {
            goto end;
        }

        strCmdURL = selList.getURL();
    }

    if( strCmdURL.length() < 1 )
    {
        berApplet->warningBox( tr( "No command URL available"), this );
        ret = -1;
        goto end;
    }

    berApplet->log( QString( "Request URL: %1" ).arg( strCmdURL ));

    if( strMethod == "POST" && strReq.length() < 1 )
    {
        berApplet->warningBox( tr("No request available" ), this );
        mRequestText->setFocus();
        ret = -2;
        goto end;
    }

    ret = getBINFromString( &binReq, DATA_STRING, strReq );
    FORMAT_WARN_GO(ret);

    if( strMethod == "POST" )
    {
        berApplet->log( QString( "Request[%1]: %2" ).arg( strCmdType ).arg( strReq ));
        ret = JS_HTTP_requestPostBin3( strCmdURL.toStdString().c_str(), NULL, NULL, "application/jose+json", &binReq, &nStatus, &pRspHeaderList, &binRsp );
    }
    else
    {
        ret = JS_HTTP_requestGetBin3( strCmdURL.toStdString().c_str(), NULL, NULL, &nStatus, &pRspHeaderList, &binRsp );
    }

    mStatusText->setText( QString("%1").arg( nStatus ));

    if( ret == 0 )
    {
        QString strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
        mRspCmdText->setText( mCmdCombo->currentText() );
        berApplet->log( QString( "Response[%1]: %2").arg( strCmdType ).arg( strRsp ));

        if( strCmdType.toUpper() == kCmdKeyChange )
        {
            if( nStatus == 200 )
            {
                berApplet->messageBox( tr( "The key pair has been changed." ), this );
                resetKey();
            }
        }
    }
    else
    {
        berApplet->warnLog( tr( "failed to send a request to the ACME server: %1").arg( ret), this );
        goto end;
    }

    pCurList = pRspHeaderList;
    while( pCurList )
    {
        bool bVal = false;

        if( strcasecmp( pCurList->sNameVal.pName, "Replay-Nonce" ) == 0 )
        {
            berApplet->log( QString( "Replay-Nonce: %1").arg( pCurList->sNameVal.pValue ));

            if( mAutoNonceCheck->isChecked() == true )
                mNonceText->setText( pCurList->sNameVal.pValue );
            else
            {
                bVal = berApplet->yesOrNoBox( tr( "Change Nonce as %1?" ).arg( pCurList->sNameVal.pValue ), this, true );
                if( bVal == true )
                    mNonceText->setText( pCurList->sNameVal.pValue );
            }

            update();
        }

        if( strcasecmp( pCurList->sNameVal.pName, "Location" ) == 0 )
        {
            berApplet->log( QString( "Location: %1" ).arg( pCurList->sNameVal.pValue ));
            mLocationText->setText( pCurList->sNameVal.pValue );

            if( mCmdCombo->currentText().toUpper() == kCmdNewAccount.toUpper() )
            {
                bVal = berApplet->yesOrNoBox( tr( "Change KID as %1?" ).arg( pCurList->sNameVal.pValue ), this, true );
                if( bVal == true )
                    mKIDText->setText( pCurList->sNameVal.pValue );

                addCmd( kCmdAccount, pCurList->sNameVal.pValue );
            }

            QString strCmd = mCmdCombo->currentText();
            if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
            {
                addCmd( kCmdAccount, mLocationText->text() );
            }
            else if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
            {
                addCmd( kCmdOrder, mLocationText->text() );
            }
        }

        pCurList = pCurList->pNext;
    }

    if( mAutoParseCheck->isChecked() ) clickParse();

    mCmdTable->insertRow(0);
    mCmdTable->setRowHeight(0,10);
    mCmdTable->setItem(0, 0, new QTableWidgetItem( strCmdType ));
    mCmdTable->setItem(0, 1, new QTableWidgetItem( strCmdURL ));

end :
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}

int ACMEClientDlg::savePriKeyCert( const BIN *pPriKey, const BIN *pCert )
{
    int ret = 0;

    bool bVal = false;
    bVal = berApplet->yesOrNoBox( tr( "Do you want to save the private key and certificate"), this, true );
    if( bVal == true )
    {
        int nKeyType = -1;
        BIN binEncPri = {0,0};
        CertManDlg certMan;
        NewPasswdDlg newPass;
        int nPBE = -1;
        nPBE = JS_PKI_getNidFromSN( berApplet->settingsMgr()->priEncMethod().toStdString().c_str() );

        if( newPass.exec() == QDialog::Accepted )
        {
            QString strPass = newPass.mPasswdText->text();
            nKeyType = JS_PKI_getPriKeyType( pPriKey );

            ret = JS_PKI_encryptPrivateKey( nPBE, strPass.toStdString().c_str(), pPriKey, NULL, &binEncPri );
            if( ret == 0 )
            {
                ret = certMan.writePriKeyCert( &binEncPri, pCert );
                if( ret == 0 )
                    berApplet->messageLog( tr( "The private key and certificate are saved successfully" ), this );
                else
                    berApplet->warnLog( tr( "failed to save the private key and certificate" ), this );
            }
        }

        JS_BIN_reset( &binEncPri );
    }

    return ret;
}

int ACMEClientDlg::runCmd( const QString strCmd )
{
    int ret = 0;

    mCmdCombo->setCurrentText( strCmd );
    ret = clickMake();
    if( ret != 0 ) return ret;

    if( mAutoSendCheck->isChecked() == false )
    {
        ret = clickSend();
        if( ret != 0 ) return ret;
    }

    if( mAutoParseCheck->isChecked() == false )
    {
        ret = clickParse();
        if( ret != 0 ) return ret;
    }

    return JSR_OK;
}

void ACMEClientDlg::clickIssueCert()
{
    if( mCmdCombo->count() < 1 )
    {
        berApplet->warningBox( tr( "Click the directory"), this );
        mGetDirBtn->setFocus();
        return;
    }

    if( mNonceText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Click Get Nonce" ), this );
        mInfoTab->setCurrentIndex(0);
        mGetNonceBtn->setFocus();

        return;
    }

    if( mEmailText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Enter an email" ), this );
        mInfoTab->setCurrentIndex(1);
        mEmailText->setFocus();
        return;
    }

    if( mDNSList->count() < 1 )
    {
        berApplet->warningBox( tr( "Add a DNS record" ), this );
        mInfoTab->setCurrentIndex(1);
        mDNSText->setFocus();
        return;
    }

    if( mDNSList->count() > 1 )
    {
        berApplet->warningBox( tr( "Only 1 DNS is supported" ), this );
        return;
    }

    int ret = 0;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdNewAccount ), this) == false )
        return;

    if( runCmd( kCmdNewAccount ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdNewOrder ), this) == false )
        return;

    if( runCmd( kCmdNewOrder ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdAuthorization ), this) == false )
        return;

    if( runCmd( kCmdAuthorization ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdChallenge ), this) == false )
        return;

    if( runCmd( kCmdChallenge ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdFinalize ), this) == false )
        return;

    if( runCmd( kCmdFinalize ) != JSR_OK ) return;

//    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdAccount ), this) == false )
//        return;

//    if( runCmd( kCmdAccount ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdOrders ), this) == false )
        return;

    if( runCmd( kCmdOrders ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdOrder ), this) == false )
        return;

    if( runCmd( kCmdOrder ) != JSR_OK ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( kCmdCertificate ), this) == false )
        return;

    mCmdCombo->setCurrentText( kCmdCertificate );
    if( mCmdCombo->currentText() != kCmdCertificate )
    {
        berApplet->warningBox( tr( "There is no certificate command" ), this );
        return;
    }

    if( runCmd( kCmdCertificate ) != JSR_OK ) return;

    berApplet->messageBox( tr( "Certificate issuance completed"), this );
}

void ACMEClientDlg::clickThumbPrint()
{
    if( pub_key_.nLen <= 0 )
    {
        berApplet->warningBox( tr("There is no key for the account"), this );
        return;
    }

    QString strTP = ACMEObject::getThumbPrint( &pub_key_ );
    if( strTP.length() > 0 )
        berApplet->messageBox( tr( "Thumb Print: %1").arg( strTP ), this );
}

void ACMEClientDlg::clickTest()
{
    int ret = 0;
    BINList *pBinList = NULL;
    BINList *pCurList = NULL;

    const QString strPEM = "-----BEGIN CERTIFICATE-----\n"
                            "MIICUDCCATigAwIBAgIIMBER/8WeHi8wDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE\n"
                            "AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAzMGFjYjUwHhcNMjUwNzA5MDQyNDM0\n"
                            "WhcNMjUwNzE1MDQyNDMzWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGPc4\n"
                            "ZKJN9mJT4i4xZfgUeS/SuZoHktyUb0p00+5e3vW9vpdW0/DP8wH9aWe/2NvW3L4R\n"
                            "UpwoxO9a3IkY5y5w+6NxMG8wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG\n"
                            "AQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUKKSIMj6+XMau2IJvWZE8\n"
                            "2p55XWQwGQYDVR0RAQH/BA8wDYILZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQAD\n"
                            "ggEBADpYjaFPfk3jaMri/1Mm9AxS+7z3O0RAlz/aK/P+BdVNkEMVoqkKK6X/FFQO\n"
                            "1WhSLzKKFg/Vlzrs/vmLZDIsLUJhG4zAujMGJYvDhvJeLVXvkpC24vPBlQMRTQXd\n"
                            "T/UZu/rhFT48ItK6/+HPuIn7kp1XbhZFkYlUx59xZ/KgAzHg41c1JiGzvxL9q9pK\n"
                            "DZuxSlxfnaCUPCVLdfpeoH0EOzwtD22+YWF9cyk8vZavd6UJf+OuoEguR+zoIzqd\n"
                            "lKJpDVHucC8tovNy85n/LzlW7jAq3Q+S4+yFuuXHjdnhwxVfVLnhOFFvpKxrx2G8\n"
                            "j3uWzwJMUStCwKglEsZoVB9dWUY=\n"
                            "-----END CERTIFICATE-----\n"
                            "-----BEGIN CERTIFICATE-----\n"
                            "MIIDRDCCAiygAwIBAgIIAtOnX9ZwjgowDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE\n"
                            "AxMVUGViYmxlIFJvb3QgQ0EgNzkxYWRiMCAXDTI1MDcwOTAxMTgyOFoYDzIwNTUw\n"
                            "NzA5MDExODI4WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDMw\n"
                            "YWNiNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJdNcxAWbXBynq7\n"
                            "lH+w8IJI0YccCtl087dLcP5HkIUM3HQOFuG/ZvDanQlIZHvsVyigP9ZtqbxbmDpS\n"
                            "l3adAUxV4PCWfVDjSCaglbigdf0yqA66E+tZH4sqor1yZxEsz02dFL5EVcX0WWKY\n"
                            "y6RimOzVK6z54ntIMnKMoZ7wh4qw1BbjWVp6CGz0YDtMXwrQXXWCDkM0CZsKrdiq\n"
                            "4oWeSPLfT3BN3/H8qKLYmytNmDx1rAm+60EV+zkhsa1gpI/wLwl5D2r6Z1jFJ/GG\n"
                            "wuwotIEmUE8Tq7eOlU4Ds8N7IlimpU8++nJaHmRPKiPCWNa2mLlNveLLOBFDD5hw\n"
                            "XWAM2LkCAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgKEMBMGA1UdJQQMMAoGCCsGAQUF\n"
                            "BwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCikiDI+vlzGrtiCb1mRPNqe\n"
                            "eV1kMB8GA1UdIwQYMBaAFI3ACZiL36/ODHbWKFqWj7e6Po+xMA0GCSqGSIb3DQEB\n"
                            "CwUAA4IBAQBhYxn58dCYTMW6vMAAgBrKrVR4SDR02V6uWDPogEKD6EzycfpG4DSS\n"
                            "lgbKQiea34oqZ7aVNMqegW6FobqOqvje9hZRvbHox80zzHJXgDn7fHAnhWQw/oel\n"
                            "22tBHywTxovyv57IZr6gsVve10VE33QrIZCuM7PCI1wFQcogA596r3IUHJd7Pe+z\n"
                            "VgMn2CtjbngLmqeFXqkvHT/L+c8TmcQr8zm+Ye7h+LUnZH26uL491/M1HSf7w0qv\n"
                            "i0wOAUctRfh+zxrkOIG7FWYRBvVNoaTtFSa2lUET6BWDwJP+59nK5udMcR3/vCLC\n"
                            "56vm5ED/Aq+nnYXB8/Gvt7REp+VxvHgc\n"
                            "-----END CERTIFICATE-----\n";

    berApplet->log( QString( "PEM Length: %1").arg( strPEM.length() ));

    ret = JS_BIN_decodePEMList( strPEM.toStdString().c_str(), &pBinList );
    berApplet->log( QString( "decodePEMList ret: %1").arg( ret ));

    pCurList = pBinList;

    while( pCurList )
    {
        JCertInfo sCertInfo;
        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        ret = JS_PKI_getCertInfo( &pCurList->Bin, &sCertInfo, NULL );
        berApplet->log( QString( "getCertInfo ret: %1").arg( ret ));

        if( ret == 0 ) berApplet->log( QString( "SubjectDN : %1" ).arg( sCertInfo.pSubjectName ));

        JS_PKI_resetCertInfo( &sCertInfo );
        pCurList = pCurList->pNext;
    }

    if( pBinList ) JS_BIN_resetList( &pBinList );
}
