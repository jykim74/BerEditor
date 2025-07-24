#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

#include "chall_test_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_man_dlg.h"
#include "acme_tree_dlg.h"
#include "one_list_dlg.h"
#include "two_list_dlg.h"

#include "js_http.h"
#include "js_pki.h"

const QString kChallTestGroup = "ChallTest";
const QString kChallTestServer = "ChallTestServer";
const QString kChallTestPort = "ChallTestPort";

const QStringList kCmdTypeList = {
    kCmdHTTP01, kCmdDNS01, kCmdTLS_ALPN01, kCmdCLEARUP, kCmdCLEAR_TXT };

const QStringList kCmdPathList = {
    "/present-http-01",
    "/set-txt",
    "/present-tls-alpn-01",
    "/cleanup",
    "/clear-txt"
};

const QStringList kManTypeList = {
    kManSetDefaultIPV4, kManSetDefaultIPV6, kManAddA, kManClearA,
    kManAddAAAA, kManClearAAAA, kManAddCAA, kManClearCAA,
    kManSetCName, kManClearCName, kManServerFail, kManAddHTTP01,
    kManDelHTTP01, kManAddRedirect, kManDelRedirect, kManSetTxt, kManClearTxt,
    kManAddTLS_ALPN01, kManDelTLS_ALPN01, kManHTTPRequestHistory, kManDNSRequestHistory,
    kManClearRequestHistory
};

const QStringList kManPathList = {
    kManSetDefaultIPV4Path, kManSetDefaultIPV6Path, kManAddAPath, kManClearAPath,
    kManAddAAAAPath, kManClearAAAAPath, kManAddCAAPath, kManClearCAAPath,
    kManSetCNamePath, kManClearCNamePath, kManServerFailPath, kManAddHTTP01Path,
    kManDelHTTP01Path, kManAddRedirectPath, kManDelRedirectPath, kManSetTxtPath, kManClearTxtPath,
    kManAddTLS_ALPN01Path, kManDelTLS_ALPN01Path, kManHTTPRequestHistoryPath, kManDNSRequestHistoryPath,
    kManClearRequestHistoryPath
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
    connect( mValueClearBtn, SIGNAL(clicked()), this, SLOT(clickValueClear()));
    connect( mValueListBtn, SIGNAL(clicked()), this, SLOT(clickValueList()));
    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));
    connect( mRequestViewBtn, SIGNAL(clicked()), this, SLOT(clickRequestView()));
    connect( mResponseViewBtn, SIGNAL(clicked()), this, SLOT(clickResponseView()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mValueClearBtn->setFixedWidth(34);
    mRequestClearBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ChallTestDlg::~ChallTestDlg()
{
    QString strServer = mServerText->text();
    int nPort = mPortText->text().toInt();

    if( strServer != getEnvServer() )
        setEnvServer( strServer );

    if( nPort != getEnvPort() )
        setEnvPort( nPort );
}

void ChallTestDlg::initUI()
{
    QString strServer = getEnvServer();
    int nPort = getEnvPort();

    mServerText->setText( strServer );
    mPortText->setText( QString("%1").arg( nPort ));

    for( int i = 0; i < kManTypeList.size(); i++ )
    {
        QString strMan = kManTypeList.at(i);
        QString strPath = kManPathList.at(i);

        mCmdCombo->addItem( strMan, strPath );
    }

    changeCmdType(0);
}

void ChallTestDlg::changeCmdType( int index )
{
    QString strCmd = mCmdCombo->currentText();
    QString strPath = mCmdCombo->currentData().toString();

    mCmdPathText->setText( strPath );

    setHost( "Host", false );
    setValue( "Value", false );
    mValueListBtn->setEnabled( false );
    mValueClearBtn->setEnabled( false );
    mValueText->setReadOnly( false );
    mValueText->setStyleSheet( "" );

    if( strCmd == kManSetDefaultIPV4 || strCmd == kManSetDefaultIPV6 )
    {
        setHost( "ip" );
    }
    else if( strCmd == kManAddA || strCmd == kManAddAAAA )
    {
        setHost( "host" );
        setValue( "addresses" );
        mValueText->setReadOnly(true);
        mValueText->setStyleSheet( kReadOnlyStyle );
        mValueListBtn->setEnabled( true );
    }
    else if( strCmd == kManClearA || strCmd == kManClearAAAA )
    {
        setHost( "host" );
    }
    else if( strCmd == kManAddCAA )
    {
        setHost( "host" );
        setValue( "policies" );
        mValueText->setReadOnly(true);
        mValueText->setStyleSheet( kReadOnlyStyle );
        mValueListBtn->setEnabled(true);
    }
    else if( strCmd == kManSetCName || strCmd == kManClearCName )
    {
        setHost( "host" );
        setValue( "target" );
    }
    else if( strCmd == kManClearCAA || strCmd == kManServerFail )
    {
        setHost( "host" );
    }
    else if( strCmd == kManAddHTTP01 )
    {
        setHost( "token" );
        setValue( "content" );
    }
    else if( strCmd == kManDelHTTP01 )
    {
        setHost( "token" );
    }
    else if( strCmd == kManAddRedirect )
    {
        setHost( "path" );
        setValue( "targetURL" );
    }
    else if( strCmd == kManDelRedirect )
    {
        setHost( "path" );
    }
    else if( strCmd == kManSetTxt )
    {
        setHost( "host" );
        setValue( "value" );
    }
    else if( strCmd == kManClearTxt )
    {
        setHost( "host" );
    }
    else if( strCmd == kManAddTLS_ALPN01 )
    {
        setHost( "host" );
        setValue( "content" );
    }
    else if( strCmd == kManDelTLS_ALPN01 )
    {
        setHost( "host" );
    }
    else if( strCmd == kManHTTPRequestHistory || strCmd == kManDNSRequestHistory || strCmd == kManClearRequestHistory )
    {
        setHost( "host" );
    }
}

void ChallTestDlg::setHost( const QString strLabel, bool bEnable )
{
    mHostLabel->setText( strLabel );
    mHostLabel->setEnabled( bEnable );
    mHostText->setEnabled( bEnable );
}

void ChallTestDlg::setValue( const QString strLabel, bool bEnable )
{
    mValueLabel->setText( strLabel );
    mValueLabel->setEnabled( bEnable );
    mValueText->setEnabled( bEnable );
    mValueClearBtn->setEnabled( bEnable );
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

int ChallTestDlg::makeRequest()
{
    QJsonObject jObj;
    QJsonDocument jDoc;
    QString strRsp;

    QString strHost = mHostText->text();
    QString strValue = mValueText->text();

    QString strHostLabel = mHostLabel->text();
    QString strValueLabel = mValueLabel->text();

    if( mHostLabel->isEnabled() == true )
    {
        if( strHost.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a %1" ).arg( strHostLabel ), this );
            mHostText->setFocus();
            return -1;
        }

        jObj[strHostLabel] = strHost;
    }

    if( mValueLabel->isEnabled() == true )
    {
        if( strValue.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a %1" ).arg( strValueLabel ), this );
            mValueText->setFocus();
            return -1;
        }

        if( strValueLabel == "policies" )
        {
            QJsonArray jSubArr;
            QStringList listVal = strValue.split( "#" );

            for( int i = 0; i < listVal.size(); i++ )
            {
                QString strOne = listVal.at(i);
                QStringList nameVal = strOne.split("$");
                if( nameVal.size() < 2 ) continue;

                QJsonObject jSubObj;
                jSubObj["tag"] = nameVal.at(0);
                jSubObj["vallue"] = nameVal.at(1);

                jSubArr.append( jObj );
            }

            jObj[strValueLabel] = jSubArr;
        }
        else if( strValueLabel == "addresses" )
        {
            QJsonArray jSubArr;
            QStringList listVal = strValue.split( "#" );

            for( int i = 0; i < listVal.size(); i++ )
            {
                QString strOne = listVal.at(i);
                jSubArr.append( strOne );
            }

            jObj[strValueLabel] = jSubArr;
        }
        else
        {
            jObj[strValueLabel] = strValue;
        }
    }

    jDoc.setObject( jObj );
    strRsp = jDoc.toJson();

    mRequestText->setPlainText( strRsp );

    return 0;
}

int ChallTestDlg::clickMake()
{
    int ret = 0;

    QString strCmd = mCmdCombo->currentText();
    ret = makeRequest();

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
    berApplet->log( QString( "ChallTest URL: %1" ).arg( strURL ));

    getBINFromString( &binReq, DATA_STRING, strRequest );

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

void ChallTestDlg::clickValueList()
{
    QString strValueLabel = mValueLabel->text();

    if( strValueLabel == "policies" )
    {
        TwoListDlg twoList;
        QString listValue;

        twoList.setNames( "tag", "value" );

        if( twoList.exec() != QDialog::Accepted )
            return;

        listValue = twoList.getListString();
        mValueText->setText( listValue );
    }
    else
    {
        QString strLabel = mValueLabel->text();
        QString strValue = mValueText->text();

        QString strList;

        OneListDlg oneList;
        oneList.setName( strLabel );

        if( strValue.length() > 0 ) oneList.addName( strValue );

        if( oneList.exec() != QDialog::Accepted )
            return;

        strList = oneList.getListString();
        mValueText->setText( strList );
    }
}

void ChallTestDlg::clickValueClear()
{
    mValueText->clear();
}

void ChallTestDlg::setEnvServer( const QString strServer )
{
    QSettings settings;
    settings.beginGroup( kChallTestGroup );
    settings.setValue( kChallTestServer, strServer );
    settings.endGroup();
}

void ChallTestDlg::setEnvPort( int nPort )
{
    QSettings settings;
    settings.beginGroup( kChallTestGroup );
    settings.setValue( kChallTestPort, nPort );
    settings.endGroup();
}

const QString ChallTestDlg::getEnvServer()
{
    QString strServer;

    QSettings settings;
    settings.beginGroup( kChallTestGroup );
    strServer = settings.value( kChallTestServer, "127.0.0.1" ).toString();
    settings.endGroup();

    return strServer;
}

int ChallTestDlg::getEnvPort()
{
    int nPort = -1;

    QSettings settings;
    settings.beginGroup( kChallTestGroup );
    nPort = settings.value( kChallTestPort, "8055" ).toInt();
    settings.endGroup();

    return nPort;
}
