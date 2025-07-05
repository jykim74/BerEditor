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

ACMEClientDlg::ACMEClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mGetNonceBtn, SIGNAL(clicked()), this, SLOT(clickGetNonce()));
    connect( mGetDirBtn, SIGNAL(clicked()), this, SLOT(clickGetDirectory()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mClearRequestBtn, SIGNAL(clicked()), this, SLOT(clickClearRequest()));
    connect( mClearResponseBtn, SIGNAL(clicked()), this, SLOT(clickClearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));
    connect( mParserBtn, SIGNAL(clicked()), this, SLOT(clickParse()));
    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmd(int)));

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

}

void ACMEClientDlg::initUI()
{
    mMethodCombo->addItems( kMethodList );
    mRspCombo->addItems( kParserList );
    mHashCombo->addItems( kHashList );

    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mEmailText->setText( "jykim74@gmail.com" );
    mDNSText->setText( "www.test.com" );
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

void ACMEClientDlg::clickParse()
{
    QJsonDocument jsonDoc;

    QString strRsp = mResponseText->toPlainText();
    QString strParse = mRspCombo->currentText();

    if( strRsp.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response"), this );
        mResponseText->setFocus();
        return;
    }

    jsonDoc = QJsonDocument::fromJson( strRsp.toLocal8Bit() );
    berApplet->log( jsonDoc.toJson() );
}

void ACMEClientDlg::changeCmd( int index )
{
    QString strURL = mCmdCombo->currentData().toString();
    mCmdText->setText( strURL );
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

    for( int i = 0; i < listKeys.size(); i++ )
    {
        QString strCmd = listKeys.at(i);
        berApplet->log( QString( "Key: %1").arg( listKeys.at(i)));
        QString strValue = jObj[strCmd].toString();
        berApplet->log( QString( "Value: %1" ).arg( strValue ));

        if( strCmd.toUpper() == kCmdNewNonce.toUpper() )
            mNonceURLText->setText( strValue );

        if( strCmd != "meta" )
            mCmdCombo->addItem( strCmd, strValue );
    }

end :
    JS_BIN_reset( &binRsp );
}

int ACMEClientDlg::makeKeyExchange( QJsonObject& object )
{
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
    return 0;
}

int ACMEClientDlg::makeNewOrder( QJsonObject& object )
{
    QString strDNS = mDNSText->text();

    if( strDNS.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a DNS" ), this );
        mDNSText->setFocus();
        return -1;
    }

    object = ACMEObject::getIdentifiers( "dns", strDNS );
    return 0;
}

int ACMEClientDlg::makeRenewalInfo( QJsonObject& object )
{
    return 0;
}

int ACMEClientDlg::makeRevokeCert( QJsonObject& object )
{
    return 0;
}

void ACMEClientDlg::clickMake()
{
    int ret = 0;
    int nKeyType = -1;
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    ACMEObject acmeObj;
    QString strCmd = mCmdCombo->currentText();
    QString strHash = mHashCombo->currentText();
    QString strKID = mKIDText->text();

    QString strJWK;
    QJsonObject objJWK;
    QJsonObject objPayload;
    QJsonObject objProtected;

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    QString strPubPath = keyPairMan.getPubPath();
    QString strPriPath = keyPairMan.getPriPath();
    QString strName = keyPairMan.getName();
    QString strNonce = mNonceText->text();
    QString strAlg;
    QString strURL = mCmdText->text();

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &binPub, strHash, strName );


    if( strCmd.toUpper() == kCmdKeyChange.toUpper() )
        ret = makeKeyExchange(objPayload);
    else if( strCmd.toUpper() == kCmdNewAccount.toUpper() )
        ret = makeNewAccount(objPayload);
    else if( strCmd.toUpper() == kCmdNewNonce.toUpper() )
        ret = makeNewNonce(objPayload);
    else if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
        ret = makeNewOrder(objPayload);
    else if( strCmd.toUpper() == kCmdRenewalInfo.toUpper() )
        ret = makeRenewalInfo(objPayload);
    else if( strCmd.toUpper() == kCmdRevokeCert.toUpper() )
        ret = makeRevokeCert(objPayload);
    else
    {
        berApplet->warningBox( tr( "Invalid command: %1").arg( strCmd ), this );
        goto end;
    }

    acmeObj.setPayload( objPayload );
    berApplet->log( QString("Payload: %1").arg( acmeObj.getPayloadJSON() ));

    if( strKID.length() > 0 )
        objProtected = acmeObj.getKidProtected( strAlg, strKID, strNonce, strURL );
    else
        objProtected = acmeObj.getJWKProtected( strAlg, objJWK, strNonce, strURL );

    acmeObj.setProtected( objProtected );

    berApplet->log( QString("Protected: %1").arg( acmeObj.getProtectedJSON() ));

    acmeObj.setSignature( &binPri, strHash );

    //mRequestText->setPlainText( acmeObj.getJson() );
    mRequestText->setPlainText( acmeObj.getPacketJson() );

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
}

void ACMEClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strCmd = mCmdText->text();
    QString strMethod = mMethodCombo->currentText();

    QString strLink;
    JNameValList *pRspHeaderList = NULL;
    JNameValList *pCurList = NULL;

    if( strCmd.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no command URL"), this );
        mURLCombo->setFocus();
        goto end;
    }

    if( strMethod == "POST" && strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        mRequestText->setFocus();
        goto end;
    }

    getBINFromString( &binReq, DATA_STRING, strReq );

    if( strMethod == "POST" )
        ret = JS_HTTP_requestPostBin3( strCmd.toStdString().c_str(), NULL, NULL, "application/jose+json", &binReq, &nStatus, &pRspHeaderList, &binRsp );
    else
        ret = JS_HTTP_requestGetBin3( strCmd.toStdString().c_str(), NULL, NULL, &nStatus, &pRspHeaderList, &binRsp );


    if( ret == 0 )
    {
        QString strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
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
            bVal = berApplet->yesOrNoBox( tr( "Change Nonce?" ), this, true );
            if( bVal == true )
                mNonceText->setText( pCurList->sNameVal.pValue );
        }
        else if( strcasecmp( pCurList->sNameVal.pName, "Location" ) == 0 )
        {
            bVal = berApplet->yesOrNoBox( tr( "Change KID?" ), this, true );
            if( bVal == true )
                mKIDText->setText( pCurList->sNameVal.pValue );
        }

        pCurList = pCurList->pNext;
    }

end :
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}
