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

#include "js_bin.h"
#include "js_pki.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_error.h"

const QString kACMEUsedURL = "ACMEUsedURL";
const QStringList kCmdList = { "", "new-account", "new_order", "challenge", "finalize-order" };

ACMEClientDlg::ACMEClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mClearRequestBtn, SIGNAL(clicked()), this, SLOT(clickClearRequest()));
    connect( mClearResponseBtn, SIGNAL(clicked()), this, SLOT(clickClearResponse()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(changeRequest()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(changeResponse()));

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

void ACMEClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strURL = mURLCombo->currentText();
    QString strCmd = mCmdCombo->currentText();
    QString strLink;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert ACME URL"), this );
        mURLCombo->setFocus();
        goto end;
    }

    if( strReq.length() < 1 )
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

    ret = JS_HTTP_requestPostBin( strLink.toStdString().c_str(), "application/jose+json", &binReq, &nStatus, &binRsp );
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
