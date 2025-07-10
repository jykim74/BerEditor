#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "chall_test_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_man_dlg.h"
#include "acme_tree_dlg.h"

#include "js_http.h"
#include "js_pki.h"

const QStringList kCmdTypeList = {
    kCmdHTTP01, kCmdDNS01, kCmdTLS_ALPN01, kCmdCLEARUP, kCmdCLEAR_TXT };

const QStringList kCmdPathList = {
    "/present-http-01",
    "/present-tls-alpn-01",
    "/set-txt",
    "/cleanup",
    "/clear-txt"
};

ChallTestDlg::ChallTestDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCmdType(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));
    connect( mRequestViewBtn, SIGNAL(clicked()), this, SLOT(clickRequestView()));
    connect( mResponseViewBtn, SIGNAL(clicked()), this, SLOT(clickResponseView()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ChallTestDlg::~ChallTestDlg()
{

}

void ChallTestDlg::initUI()
{
    mServerText->setText( "127.0.0.1" );
    mPortText->setText( "5002" );

    mCmdCombo->addItems( kCmdTypeList );
}

void ChallTestDlg::changeCmdType( int index )
{
    QString strCmd = mCmdCombo->currentText();

    mValue1Label->setText( "value" );
    mValue2Label->setText( "value2" );
    mValue1Text->setReadOnly(true);
    mValue2Text->setReadOnly(true);

    if( strCmd == kCmdTLS_ALPN01 )
    {
        mUseTLSCheck->setEnabled(false);
        mValue1Label->setText( "cert" );
        mValue2Label->setText( "key" );

        mValue1Text->setText( tr("PEM Certificate") );
        mValue2Text->setText( tr("PEM Private Key") );
    }
    else
    {
        mUseTLSCheck->setEnabled(true);
    }

    if( strCmd == kCmdHTTP01 )
    {
        mValue1Label->setText( "token" );
        mValue2Label->setText( "keyAuth" );
        mValue1Text->setReadOnly( false );
        mValue2Text->setReadOnly( false );
    }
    else if( strCmd == kCmdDNS01 )
    {
        mValue1Label->setText( "value" );
        mValue1Text->setReadOnly( false );
    }

    mCmdPathText->setText( kCmdPathList.at(index ));
}

void ChallTestDlg::clearRequest()
{
    mRequestText->clear();
}

void ChallTestDlg::clearResponse()
{
    mResponseText->clear();
}

void ChallTestDlg::changeRequest()
{
    QString strRequest = mRequestText->toPlainText();
    mRequestLenText->setText( QString("%1").arg( strRequest.length()));
}

void ChallTestDlg::changeResponse()
{
    QString strResponse = mResponseText->toPlainText();
    mResponseLenText->setText( QString("%1").arg( strResponse.length()));
}

void ChallTestDlg::clickRequestView()
{
    QString strRequest = mRequestText->toPlainText();
    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no request" ), this );
        return;
    }

    ACMETreeDlg acmeTree( nullptr, false );
    acmeTree.setJson( strRequest );
    acmeTree.exec();
}

void ChallTestDlg::clickResponseView()
{
    QString strResponse = mResponseText->toPlainText();
    if( strResponse.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no response" ), this );
        return;
    }

    ACMETreeDlg acmeTree( nullptr, false );
    acmeTree.setJson( strResponse );
    acmeTree.exec();
}

int ChallTestDlg::makeHTTP01()
{
    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;

    QString strHost = mHostText->text();
    QString strValue1 = mValue1Text->text();
    QString strValue2 = mValue2Text->text();

    if( strHost.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a host" ), this );
        mHostText->setFocus();
        return -1;
    }

    if( strValue1.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a token" ), this );
        mValue1Text->setFocus();
        return -1;
    }

    if( strValue2.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a keyAuth" ), this );
        mValue2Text->setFocus();
        return -1;
    }

    jObj["host"] = strHost;
    jObj["token"] = strValue1;
    jObj["keyAuth"] = strValue2;

    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mResponseText->setPlainText( strRsp );

    return 0;
}

int ChallTestDlg::makeDNS01()
{
    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;

    QString strHost = mHostText->text();
    QString strValue1 = mValue1Text->text();

    if( strHost.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a host" ), this );
        mHostText->setFocus();
        return -1;
    }

    if( strValue1.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a value" ), this );
        mValue1Text->setFocus();
        return -1;
    }


    jObj["host"] = strHost;
    jObj["value"] = strValue1;

    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mResponseText->setPlainText( strRsp );

    return 0;
}

int ChallTestDlg::makeTLS_ALPN01()
{
    int ret = 0;
    BIN binCert = {0,0};
    BIN binPri = {0,0};
    char *pCertPEM = NULL;
    char *pPriPEM = NULL;

    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;

    QString strHost = mHostText->text();

    if( strHost.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a host" ), this );
        mHostText->setFocus();
        return -1;
    }

    CertManDlg certMan;
    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));
    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getPriKey( &binPri );
    certMan.getCert( &binCert );

    JS_BIN_encodePEM( JS_PEM_TYPE_CERTIFICATE, &binCert, &pCertPEM );
    JS_BIN_encodePEM( JS_PEM_TYPE_PRIVATE_KEY, &binPri, &pPriPEM );

    jObj["host"] = strHost;
    jObj["cert"] = pCertPEM;
    jObj["key"] = pPriPEM;

    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mResponseText->setPlainText( strRsp );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPri );
    if( pCertPEM ) JS_free( pCertPEM );
    if( pPriPEM ) JS_free( pPriPEM );

    return ret;
}

int ChallTestDlg::makeCLEANUP()
{
    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;

    QString strHost = mHostText->text();

    if( strHost.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a host" ), this );
        mHostText->setFocus();
        return -1;
    }

    jObj["host"] = strHost;

    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mResponseText->setPlainText( strRsp );

    return 0;
}

int ChallTestDlg::makeCLEAR_TXT()
{
    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;
/*
    QString strHost = mHostText->text();

    if( strHost.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a host" ), this );
        mHostText->setFocus();
        return -1;
    }

    jObj["host"] = strHost;
*/
    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mResponseText->setPlainText( strRsp );

    return 0;
}

int ChallTestDlg::clickMake()
{
    int ret = 0;

    QString strCmd = mCmdCombo->currentText();

    if( strCmd == kCmdHTTP01 )
    {
        ret = makeHTTP01();
    }
    else if( strCmd == kCmdDNS01 )
    {
        ret = makeDNS01();
    }
    else if( strCmd == kCmdTLS_ALPN01 )
    {
        ret = makeTLS_ALPN01();
    }
    else if( strCmd == kCmdCLEARUP )
    {
        ret = makeCLEANUP();
    }
    else if( strCmd == kCmdCLEAR_TXT )
    {
        ret = makeCLEAR_TXT();
    }
    else
    {
        return -1;
    }

    return ret;
}

int ChallTestDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    QString strURI = "http://";
    QString strCmd = mCmdCombo->currentText();
    QString strPath = mCmdPathText->text();
    QString strServer = mServerText->text();
    QString strPort = mPortText->text();

    QString strRequest = mRequestText->toPlainText();

    if( strRequest.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no request" ), this );
        return -1;
    }

    if( mUseTLSCheck->isChecked() ==true )
        strURI = "https://";

    QString strURL = QString( "%1%2:%3%4" ).arg( strURI ).arg( strServer ).arg( strPort ).arg( strPath);

    ret = JS_HTTP_requestPostBin2( strURL.toStdString().c_str(), NULL, NULL, "application/json", &binReq, &nStatus, &binRsp );

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

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}
