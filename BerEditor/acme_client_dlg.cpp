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

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mKIDClearBtn, SIGNAL(clicked()), this, SLOT(clickClearKID()));
    connect( mGetNonceBtn, SIGNAL(clicked()), this, SLOT(clickGetNonce()));
    connect( mGetLocationBtn, SIGNAL(clicked()), this, SLOT(clickGetLocation()));
    connect( mGetDirBtn, SIGNAL(clicked()), this, SLOT(clickGetDirectory()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
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
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
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

int ACMEClientDlg::parseOrder( QJsonObject& object )
{
    QString strCert = object["certificate"].toString();

    if( strCert.length() > 0 )
        addCmd( kCmdCertificate, strCert );
}

void ACMEClientDlg::addCmd( const QString strCmd, const QString strCmdURL )
{
    for( int i = 0; i < mCmdCombo->count(); i++ )
    {
        if( mCmdCombo->itemData( i ).toString().toUpper() == strCmdURL.toUpper() )
            return;
    }

    mCmdCombo->addItem( strCmd, strCmdURL );
}

void ACMEClientDlg::clickParse()
{
    int ret = 0;
    QJsonDocument jsonDoc;

    QString strRsp = mResponseText->toPlainText();
    QString strCmd = mRspCmdText->text();

    if( strRsp.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response"), this );
        mResponseText->setFocus();
        return;
    }

    jsonDoc = QJsonDocument::fromJson( strRsp.toLocal8Bit() );
    berApplet->log( jsonDoc.toJson() );

    QJsonObject object = jsonDoc.object();

    if( strCmd.toUpper() == kCmdNewOrder.toUpper() )
    {
        ret = parseNewOrderRsp( object );
    }
    else if( strCmd.toUpper() == kCmdAuthorization.toUpper() )
    {
        ret = parseAuthzRsp( object );
    }
    else if( strCmd.toUpper() == kCmdOrder.toUpper() )
    {
        ret = parseOrder( object );
    }

    if( ret == 0 )
        berApplet->messageBox( tr( "Parsing is done" ), this );
    else
        berApplet->warningBox( tr( "fail to parse : %1").arg( ret ), this );
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

end :
    JS_BIN_reset( &binRsp );
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

    nKeyType = JS_PKI_getPriKeyType( &pri_key_ );
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &pub_key_, strHash, "Make JWK Key" );
    objProtected = acmeObj.getJWKProtected( strAlg, objJWK, strNonce, strURL );
    acmeObj.setProtected( objProtected );
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

    CertManDlg certMan;
    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getCert( &binCert );
    JS_BIN_encodeBase64URL( &binCert, &pValue );

    object["reason"] = 1;
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
    BIN binPri = {0,0};

    MakeCSRDlg makeCSR;

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair for CSR" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return -1;

    QString strPriPath = keyPairMan.getPriPath();
    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );

    makeCSR.setInfo( tr( "Make CSR" ) );
    makeCSR.setPriKey( &binPri );

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
    object["csr"] = getBase64URL_FromHex( strHex );
    ret = 0;

end :
    JS_BIN_reset( &binPri );

    return ret;
}

void ACMEClientDlg::clickMake()
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
    QString strName;
    QString strPubPath;
    QString strPriPath;

    if( pri_key_.nLen <= 0 )
    {
        if( mUseCertManCheck->isChecked() == true )
        {
            BIN binCert = {0,0};
            CertManDlg certMan;
            certMan.setMode( ManModeSelBoth );
            certMan.setTitle( tr( "Select a sign certificate" ));

            if( certMan.exec() != QDialog::Accepted )
                return;

            certMan.getPriKey( &pri_key_ );
            certMan.getCert( &binCert );
            JS_PKI_getPubKeyFromCert( &binCert, &pub_key_ );
            JS_BIN_reset( &binCert );
            strName = certMan.getSeletedCertPath();
        }
        else
        {
            KeyPairManDlg keyPairMan;
            keyPairMan.setTitle( tr( "Select keypair" ));
            keyPairMan.setMode( KeyPairModeSelect );

            if( keyPairMan.exec() != QDialog::Accepted )
                return;

            strPubPath = keyPairMan.getPubPath();
            strPriPath = keyPairMan.getPriPath();
            strName = keyPairMan.getName();

            JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &pri_key_ );
            JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &pub_key_ );
        }
    }

    nKeyType = JS_PKI_getPriKeyType( &pri_key_ );
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &pub_key_, strHash, "Make JWK Key" );


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
    else if( strCmd.toUpper() == kCmdChallenge.toUpper() )
    {
        acmeObj.setPayload( objPayload );
    }
    else
    {

    }

//    acmeObj.setPayload( objPayload );
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

//end :
//    JS_BIN_reset( &binPub );
//    JS_BIN_reset( &binPri );

}

void ACMEClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strCmdURL = mCmdText->text();
    QString strMethod = mMethodCombo->currentText();
    QString strKID = mKIDText->text();

    QString strLink;
    JNameValList *pRspHeaderList = NULL;
    JNameValList *pCurList = NULL;

    if( strCmdURL.length() < 1 )
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

            if( mKIDText->text().length() < 1 )
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

end :
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}
