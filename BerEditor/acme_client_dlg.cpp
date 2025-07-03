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
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mClearRequestBtn, SIGNAL(clicked()), this, SLOT(clickClearRequest()));
    connect( mClearResponseBtn, SIGNAL(clicked()), this, SLOT(clickClearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));
    connect( mParserBtn, SIGNAL(clicked()), this, SLOT(clickParse()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

ACMEClientDlg::~ACMEClientDlg()
{

}

void ACMEClientDlg::initUI()
{
    mCmdCombo->addItems( kCmdList );
    mMethodCombo->addItems( kMethodList );
    mRspCombo->addItems( kParserList );

    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }
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

    for( int i = 0; i < mURLCombo->count(); i++ )
    {
        QString strPosURL = mURLCombo->itemText(i);
        if( strURL == strPosURL ) return;
    }

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kACMEUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kACMEUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }
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

void ACMEClientDlg::clickGetNonce()
{
    const char *pHeaderName = "Replay-Nonce";
//    QString strURL = mURLCombo->currentText();
    QString strURL = "https://localhost:14000/nonce-plz";
    char *pNonce = NULL;

    QUrl url( strURL );

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

void ACMEClientDlg::clickMake()
{
    BIN binPub = {0,0};
    BIN binPri = {0,0};
    ACMEObject acmeObj;

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    QString strPubPath = keyPairMan.getPubPath();
    QString strPriPath = keyPairMan.getPriPath();

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

    acmeObj.setPayload( "Payload" );
    acmeObj.setProtected( "protected" );
    acmeObj.setSignature( "Signature" );

    mRequestText->setPlainText( acmeObj.getJson() );

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
    QString strURL = mURLCombo->currentText();
    QString strCmd = mCmdCombo->currentText();
    QString strMethod = mMethodCombo->currentText();

    QString strLink;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert ACME URL"), this );
        mURLCombo->setFocus();
        goto end;
    }

    if( strMethod == "POST" && strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        mRequestText->setFocus();
        goto end;
    }

    strLink = strURL;

    if( strCmd.length() > 0 )
    {
        strLink += "/";
        strLink += strCmd;
    }

    getBINFromString( &binReq, DATA_STRING, strReq );

    if( strMethod == "POST" )
        ret = JS_HTTP_requestPostBin( strLink.toStdString().c_str(), "application/jose+json", &binReq, &nStatus, &binRsp );
    else
        ret = JS_HTTP_requestGetBin2( strLink.toStdString().c_str(), NULL, NULL, &nStatus, &binRsp );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to request : %d\n", ret );
        goto end;
    }

    if( ret == 0 )
    {
        QString strRsp = getStringFromBIN( &binRsp, DATA_STRING );
        mResponseText->setPlainText( strRsp );
        setUsedURL( strURL );
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to ACME server: %1").arg( ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}
