#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

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
#include "acme_tree_dlg.h"
#include "revoke_reason_dlg.h"
#include "chall_test_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_error.h"

const QString kACMEUsedURL = "ACMEUsedURL";
const QStringList kCmdList = { "", "newAccout", "newNonce", "newOrder", "renewalInfo", "revokeCert" };
const QStringList kMethodList = { "POST", "GET" };
const QStringList kParserList = { "dir", "error" };
const QStringList kIdentifierList = { "dns", "http" };

ACMEClientDlg::ACMEClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));
    memset( &csr_pri_key_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mKIDClearBtn, SIGNAL(clicked()), this, SLOT(clickClearKID()));
    connect( mGetNonceBtn, SIGNAL(clicked()), this, SLOT(clickGetNonce()));
    connect( mGetLocationBtn, SIGNAL(clicked()), this, SLOT(clickGetLocation()));
    connect( mGetDirBtn, SIGNAL(clicked()), this, SLOT(clickGetDirectory()));
    connect( mChallTestBtn, SIGNAL(clicked()), this, SLOT(clickChallTest()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
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
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

ACMEClientDlg::~ACMEClientDlg()
{
    resetKey();
}

void ACMEClientDlg::initUI()
{
    mMethodCombo->addItems( kMethodList );
    mHashCombo->addItems( kHashList );

    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mEmailText->setText( "jykim74@gmail.com" );
    mDNSText->setText( "example.com" );

#if defined(QT_DEBUG)
    mTestBtn->show();
    mChallTestBtn->show();
#else
    mTestBtn->hide();
    mChallTestBtn->hide();
#endif
}

void ACMEClientDlg::initialize()
{

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
    key_name_.clear();
    mKeyNameLabel->setText( key_name_ );
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

void ACMEClientDlg::clickClearKID()
{
    mKIDText->clear();
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

int ACMEClientDlg::parseNewAccountRsp( QJsonObject& object )
{
    QString strOrders = object["orders"].toString();

    if( strOrders.length() > 0 )
    {
        addCmd( kCmdOrders, strOrders );
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
    QJsonArray jArr = object["authorizations"].toArray();
    QString strFinalValue = object["finalize"].toString();

    if( strFinalValue.length() > 0 )
    {
        addCmd( kCmdFinalize, strFinalValue );
    }

    for( int i = 0; i < jArr.size(); i++ )
    {
        QString strValue = jArr.at(i).toString();

        addCmd( kCmdAuthorization, strValue );
    }

    return 0;
}

int ACMEClientDlg::parseOrdersRsp( QJsonObject& object )
{
    QJsonArray jArr = object["orders"].toArray();

    for( int i = 0; i < jArr.size(); i++ )
    {
        QString strValue = jArr.at(i).toString();
        addCmd( kCmdOrder, strValue );
    }
}

int ACMEClientDlg::parseAuthzRsp( QJsonObject& object )
{
    QJsonArray jArr = object["challenges"].toArray();

    for( int i = 0; i < jArr.count(); i++ )
    {
        QJsonObject jObj = jArr.at(i).toObject();
        QString strType = jObj["type"].toString();
        QString strURL = jObj["url"].toString();
        QString strToken = jObj["token"].toString();
        QString strStatus = jObj["status"].toString();

        addCmd( kCmdChallenge, strURL );
    }

    return 0;
}

int ACMEClientDlg::parseAccountRsp( QJsonObject& object )
{
    QString strCert = object["certificate"].toString();

    if( strCert.length() > 0 )
    {
        addCmd( kCmdCertificate, strCert );

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
    }

    return 0;
}

void ACMEClientDlg::addCmd( const QString strCmd, const QString strCmdURL )
{
    for( int i = 0; i < mCmdCombo->count(); i++ )
    {
        if( mCmdCombo->itemData( i ).toString().toUpper() == strCmdURL.toUpper() )
            return;
    }

    mCmdCombo->addItem( strCmd.toUpper(), strCmdURL );
    berApplet->log( QString( "Add command [%1 : %2]").arg( strCmd.toUpper() ).arg( strCmdURL ));
}

int ACMEClientDlg::clickParse()
{
    int ret = 0;

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

    if( nStatus >= 300 )
    {
        QString strDetail = object["detail"].toString();
        berApplet->warningBox( tr("Error: %1 status: %2").arg( strDetail) .arg( nStatus ), this);
        return -1;
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

        if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
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
        else if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
        {
            ret = parseNewAccountRsp( object );
        }
    }

    if( ret == 0 )
        berApplet->messageBox( tr( "Parsing is done" ), this );
    else
        berApplet->warningBox( tr( "fail to parse : %1").arg( ret ), this );

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
    QString strDNS = mDNSText->text();
    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS" ), this );
        mDNSText->setFocus();
        return;
    }

    for( int i = 0; i < mDNSList->count(); i++ )
    {
        QString strValue = mDNSList->item(i)->text();

        if( strValue == strDNS )
        {
            berApplet->warningBox( tr("%1 is already existed" ).arg( strDNS), this );
            return;
        }
    }

    mDNSList->addItem( strDNS );
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

    resetKey();
}

void ACMEClientDlg::clickVerify()
{
    BIN binPub = {0,0};
    QString strRequest = mRequestText->toPlainText();

    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        return;
    }

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        CertManDlg certMan;

        certMan.setMode( ManModeSelBoth );
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


    ACMEObject acmeObj;
    acmeObj.setObjectFromJson( strRequest );

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
        berApplet->warningBox( tr( "There is no request" ), this );
        return;
    }

    ACMETreeDlg acmeTree(nullptr);
    acmeTree.setJson( strRequest );
    acmeTree.exec();
}

void ACMEClientDlg::clickResponseView()
{
    QString strResponse = mResponseText->toPlainText();
    if( strResponse.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response" ), this );
        return;
    }

    ACMETreeDlg acmeTree(nullptr);
    acmeTree.setJson( strResponse );
    acmeTree.exec();
}

void ACMEClientDlg::clickGetNonce()
{
    const char *pHeaderName = "Replay-Nonce";
//    QString strURL = "https://localhost:14000/nonce-plz";
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
        pHeaderName, &pNonce );

    if( pNonce )
    {
        mNonceText->setText( pNonce );
        JS_free( pNonce );
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
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to ACME server: %1").arg( ret), this );
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
        mURLCombo->setFocus();
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
        berApplet->warnLog( tr( "fail to send a request to ACME server: %1").arg( ret), this );
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

        if( strCmd.toLower() != "meta" )
            addCmd( strCmd, strValue );
    }

    mCmdCombo->setCurrentText( kCmdLocation );

end :
    JS_BIN_reset( &binRsp );
}

void ACMEClientDlg::clickChallTest()
{
    QString strHost = mDNSText->text();

    ChallTestDlg challTest;
    challTest.mHostText->setText( strHost );
    challTest.exec();
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
    QJsonObject objJWK;
    QJsonObject objPayload;
    QJsonObject objProtected;

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a old certificate" ));

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
        keyPairMan.setTitle( tr( "Select old keypair" ));
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
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &binPub, strHash, strName );
    objProtected = acmeObj.getJWKProtected( strAlg, objJWK, strNonce, strURL );

    acmeObj.setProtected( objProtected );
    acmeObj.setPayload( objPayload );
    acmeObj.setSignature( &pri_key_, strHash );

    object["account"] = strAccount;
    object["oldKey"] = acmeObj.getObject();

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
//    QString strOrders = "https://example.com/acme/orders/rzGoeA";
    QString strOrders;

    QStringList listEmail;

    if( strEmail.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a email" ), this );
        mEmailText->setFocus();
        return -1;
    }

    listEmail.append( strEmail );

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
        berApplet->warningBox( tr( "Enter a identifier" ), this );
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

    if( strEmail.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a email" ), this );
        mEmailText->setFocus();
        return -1;
    }

    jValue = QString( "mailto: %1").arg( strEmail );
    jArr.append( jValue );

    object["contact"] = jArr;

    return 0;
}

int ACMEClientDlg::clickMake()
{
    int ret = 0;
    int nKeyType = -1;

    ACMEObject acmeObj;
    QString strCmd = mCmdCombo->currentText();
    QString strHash = mHashCombo->currentText();
    QString strKID = mKIDText->text();

    QString strJWK;
    QJsonObject objJWK;
    QJsonObject objPayload;
    QJsonObject objProtected;

    QString strNonce = mNonceText->text();
    QString strAlg;
    QString strURL = mCmdText->text();

    if( pri_key_.nLen <= 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            JCertInfo sCertInfo;
            CertManDlg certMan;

            memset( &sCertInfo, 0x00, sizeof(sCertInfo));

            certMan.setMode( ManModeSelBoth );
            certMan.setTitle( tr( "Select a sign certificate" ));

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
            keyPairMan.setTitle( tr( "Select keypair" ));
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
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &pub_key_, strHash, key_name_ );


    if( strCmd.toUpper() == kCmdKeyChange.toUpper() )
    {
        ret = makeKeyExchange(objPayload);
        acmeObj.setPayload( objPayload );
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
    }
    else
    {

    }

    berApplet->log( QString("Payload: %1").arg( acmeObj.getPayloadJSON() ));

    if( strKID.length() > 0 )
        objProtected = acmeObj.getKidProtected( strAlg, strKID, strNonce, strURL );
    else
        objProtected = acmeObj.getJWKProtected( strAlg, objJWK, strNonce, strURL );

    acmeObj.setProtected( objProtected );

    berApplet->log( QString("Protected: %1").arg( acmeObj.getProtectedJSON() ));

    acmeObj.setSignature( &pri_key_, strHash );

    mRequestText->setPlainText( acmeObj.getPacketJson() );

    mResponseText->clear();
    mRspCmdText->clear();
    mStatusText->clear();

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

    QString strLink;
    JNameValList *pRspHeaderList = NULL;
    JNameValList *pCurList = NULL;

    if( strCmdURL.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no command URL"), this );
        mURLCombo->setFocus();
        ret = -1;
        goto end;
    }

    if( strMethod == "POST" && strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        mRequestText->setFocus();
        ret = -2;
        goto end;
    }

    getBINFromString( &binReq, DATA_STRING, strReq );

    if( strMethod == "POST" )
        ret = JS_HTTP_requestPostBin3( strCmdURL.toStdString().c_str(), NULL, NULL, "application/jose+json", &binReq, &nStatus, &pRspHeaderList, &binRsp );
    else
        ret = JS_HTTP_requestGetBin3( strCmdURL.toStdString().c_str(), NULL, NULL, &nStatus, &pRspHeaderList, &binRsp );

    mStatusText->setText( QString("%1").arg( nStatus ));

    if( ret == 0 )
    {
        QString strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
        mRspCmdText->setText( mCmdCombo->currentText() );
        berApplet->log( QString( "Response: %1").arg( strRsp ));
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to ACME server: %1").arg( ret), this );
        goto end;
    }

    pCurList = pRspHeaderList;
    while( pCurList )
    {
        bool bVal = false;

        if( strcasecmp( pCurList->sNameVal.pName, "Replay-Nonce" ) == 0 )
        {
            berApplet->log( QString( "Replay-Nonce: %1").arg( pCurList->sNameVal.pValue ));
            bVal = berApplet->yesOrNoBox( tr( "Change Nonce as %1?" ).arg( pCurList->sNameVal.pValue ), this, true );
            if( bVal == true )
                mNonceText->setText( pCurList->sNameVal.pValue );
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
            }

            QString strCmd = mCmdCombo->currentText();
            if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
            {
                addCmd( kCmdOrder, mLocationText->text() );
            }
            else if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
            {
                addCmd( kCmdAccount, mLocationText->text() );
            }
        }

        pCurList = pCurList->pNext;
    }

    if( mAutoParseCheck->isChecked() ) clickParse();

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
    bVal = berApplet->yesOrNoBox( tr( "Are you save the private key and certificate"), this, true );
    if( bVal == true )
    {
        int nKeyType = -1;
        BIN binEncPri = {0,0};
        CertManDlg certMan;
        NewPasswdDlg newPass;

        if( newPass.exec() == QDialog::Accepted )
        {
            QString strPass = newPass.mPasswdText->text();
            nKeyType = JS_PKI_getPriKeyType( pPriKey );

            ret = JS_PKI_encryptPrivateKey( nKeyType, -1, strPass.toStdString().c_str(), pPriKey, NULL, &binEncPri );
            if( ret == 0 )
            {
                ret = certMan.writePriKeyCert( &binEncPri, pCert );
                if( ret == 0 )
                    berApplet->messageLog( tr( "The private key and certificate are saved successfully" ), this );
                else
                    berApplet->warnLog( tr( "faied to save private key and certificate" ), this );
            }
        }

        JS_BIN_reset( &binEncPri );
    }

    return ret;
}

void ACMEClientDlg::clickIssueCert()
{
    if( mCmdCombo->count() < 1 )
    {
        berApplet->warningBox( tr( "Click on the directory"), this );
        mGetDirBtn->setFocus();
        return;
    }

    if( mNonceText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Click on the Get Nonce" ), this );
        mGetNonceBtn->setFocus();
        return;
    }

    if( mEmailText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a email" ), this );
        mEmailText->setFocus();
        return;
    }

    if( mDNSList->count() < 1 )
    {
        berApplet->warningBox( tr( "Add a DNS" ), this );
        mDNSText->setFocus();
        return;
    }

    int ret = 0;
    mCmdCombo->setCurrentText( kCmdNewAccount );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdNewOrder );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    ret = clickParse();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdAuthorization );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    ret = clickParse();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdChallenge );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdFinalize );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdAccount );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    ret = clickParse();
    if( ret != 0 ) return;

    mCmdCombo->setCurrentText( kCmdCertificate );
    ret = clickMake();
    if( ret != 0 ) return;

    if( berApplet->yesOrNoBox( tr("Continue %1?").arg( mCmdCombo->currentText()), this) == false )
        return;

    ret = clickSend();
    if( ret != 0 ) return;

    ret = clickParse();
    if( ret != 0 ) return;

    berApplet->messageBox( tr( "Certificate issuance completed"), this );
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
