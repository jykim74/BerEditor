#include <QSettings>

#include "secp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_scep.h"
#include "js_http.h"
#include "js_pki_x509.h"

const QString kSECPUsedURL = "SECPUsedURL";

SECPClientDlg::SECPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);


    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

    connect( mFindCACertBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(viewCACert()));
    connect( mCACertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCACert()));
    connect( mCACertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCACert()));

    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodePriKey()));
    connect( mPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));

    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mGetCABtn, SIGNAL(clicked()), this, SLOT(clickGetCA()));
    connect( mMakeIssueBtn, SIGNAL(clicked()), this, SLOT(clickMakeIssue()));
    connect( mMakeUpdateBtn, SIGNAL(clicked()), this, SLOT(clickMakeUpdate()));
    connect( mMakeGetCRLBtn, SIGNAL(clicked()), this, SLOT(clickMakeGetCRL()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);

    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);
    mPriKeyDecodeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);
#endif

    initialize();
}

SECPClientDlg::~SECPClientDlg()
{

}

void SECPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }
}

QStringList SECPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kSECPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void SECPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kSECPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kSECPUsedURL, list );
    settings.endGroup();
}

int SECPClientDlg::getCA( BIN *pCA )
{
    int ret = 0;
    int nStatus = 0;

    QString strURL = mURLCombo->currentText();

    CertInfoDlg certInfo;

    if( strURL.length() < 1 ) return -1;

    strURL += "/pkiclient.exe?operation=GetCACert";

    ret = JS_HTTP_requestGetBin2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        &nStatus,
        pCA );

    return ret;
}

int SECPClientDlg::readPrivateKey( BIN *pPriKey )
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binDec = {0,0};
    BIN binInfo = {0,0};

    QString strPriPath = mPriKeyPathText->text();
    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "select a private key"), this );
        return -1;
    }

    ret = JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binData );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to read a private key: %1").arg( ret ), this );
        return  -1;
    }

    if( mEncPriKeyCheck->isChecked() )
    {
        QString strPasswd = mPasswdText->text();
        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password"), this );
            ret = -1;
            goto end;
        }

        ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binData, &binInfo, &binDec );
        if( ret != 0 )
        {
            berApplet->warningBox( tr( "failed to decrypt private key:%1").arg( ret ), this );
            mPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        JS_BIN_copy( pPriKey, &binDec );
        ret = 0;
    }
    else
    {
        JS_BIN_copy( pPriKey, &binData );
        ret = 0;
    }

end :
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDec );
    JS_BIN_reset( &binInfo );

    return ret;
}

void SECPClientDlg::clickClearURL()
{

}

void SECPClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCACertPathText->setText( filePath );
}

void SECPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void SECPClientDlg::findPriKey()
{
    QString strPath = mPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriKeyPathText->setText( filePath );
}

void SECPClientDlg::typeCACert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void SECPClientDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}

void SECPClientDlg::typePriKey()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The private key type is %1").arg( getKeyTypeName( nType )), this);

    JS_BIN_reset( &binData );
}

void SECPClientDlg::viewCACert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void SECPClientDlg::viewCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}


void SECPClientDlg::decodeCACert()
{
    BIN binData = {0,0};
    QString strFile = mCACertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void SECPClientDlg::decodeCert()
{
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void SECPClientDlg::decodePriKey()
{
    BIN binData = {0,0};
    QString strFile = mPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void SECPClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void SECPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void SECPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void SECPClientDlg::clearResponse()
{
    mResponseText->clear();
}

void SECPClientDlg::requestChanged()
{
    int nLen = mRequestText->toPlainText().length() / 2;
    mRequestLenText->setText( QString("%1").arg( nLen ) );
}

void SECPClientDlg::responseChanged()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ) );
}

void SECPClientDlg::clickClearAll()
{
    clearRequest();
    clearResponse();
}

void SECPClientDlg::clickGetCA()
{
    int ret = 0;
    int nStatus = 0;

    BIN binCA = {0,0};
    QString strURL = mURLCombo->currentText();

    CertInfoDlg certInfo;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SECP URL"), this );
        return;
    }

    strURL += "/pkiclient.exe?operation=GetCACert";

    ret = JS_HTTP_requestGetBin2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        &nStatus,
        &binCA );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP get [%1:%2]").arg(ret).arg(nStatus));
        goto end;
    }

    if( mCACertPathText->text().length() < 1 )
        mCACertPathText->setText( strURL );

    certInfo.setCertBIN( &binCA );
    certInfo.exec();

end :
    JS_BIN_reset( &binCA );
}

void SECPClientDlg::clickMakeIssue()
{

}

void SECPClientDlg::clickMakeUpdate()
{

}

void SECPClientDlg::clickMakeGetCRL()
{

}

void SECPClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strReq = mRequestText->toPlainText();

    CertInfoDlg certInfo;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter SECP URL"), this );
        return;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        goto end;
    }

    getBINFromString( &binReq, DATA_HEX, strReq );

    strURL += "/pkiclient.exe?operation=PKIOperation";

    ret = JS_HTTP_requestPostBin2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-pki-message",
        &binReq,
        &nStatus,
        &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        berApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( ret ).arg( nStatus ), this );
        goto end;
    }

    mResponseText->setPlainText( getHexString( &binRsp ));
    setUsedURL( strURL );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void SECPClientDlg::clickVerify()
{
    int ret = 0;

    BIN binRsp = {0,0};
    BIN binCA = {0,0};
    BIN binPriKey = {0,0};
    BIN binNonce = {0,0};

    BIN binData = {0,0};

    QString strRsp = mResponseText->toPlainText();
    QString strPriPath = mPriKeyPathText->text();
    QString strNonce = mNonceText->text();
    QString strTransID = mTransIDText->text();

    if( strRsp.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        goto end;
    }

    if( strPriPath.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPriKey );

    getBINFromString( &binRsp, DATA_HEX, strRsp );
    getBINFromString( &binNonce, DATA_HEX, strNonce );


    ret = getCA( &binCA );
    if( ret != 0 ) goto end;

    ret = JS_SCEP_parseCertRsp(
        &binRsp,
        &binCA,
        &binPriKey,
        &binNonce,
        strTransID.toStdString().c_str(),
        &binData );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( "failed to verify Rsp" ), this );
        goto end;
    }
    else
    {
        berApplet->messageLog( tr("Verify OK" ), this );
    }

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binData );
}
