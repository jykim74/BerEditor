#include <QSettings>

#include "tsp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"
#include "settings_mgr.h"
#include "tst_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_tsp.h"
#include "js_http.h"

const QString kTSPUsedURL = "TSPUsedURL";

TSPClientDlg::TSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mURLClearBtn, SIGNAL(clicked()), this, SLOT(clickClearURL()));
    connect( mTSTInfoBtn, SIGNAL(clicked()), this, SLOT(clickTSTInfo()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));

    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));

    connect( mFindSrvCertBtn, SIGNAL(clicked()), this, SLOT(findSrvCert()));
    connect( mSrvCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSrvCert()));
    connect( mSrvCertDeocodeBtn, SIGNAL(clicked()), this, SLOT(decodeSrvCert()));
    connect( mSrvCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSrvCert()));

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mSrvCertDeocodeBtn->setFixedWidth(34);
    mSrvCertViewBtn->setFixedWidth(34);
    mSrvCertTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);

    mResponseDecodeBtn->setFixedWidth(34);
    mResponseClearBtn->setFixedWidth(34);

#endif

    initialize();
}

TSPClientDlg::~TSPClientDlg()
{

}

void TSPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mInputTypeCombo->addItems( kValueTypeList );

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }

    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( setMgr->defaultHash() );

    mPolicyText->setText( "1.2.3.4" );
}

QStringList TSPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void TSPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTSPUsedURL, list );
    settings.endGroup();
}

void TSPClientDlg::clickClearURL()
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTSPUsedURL, "" );
    settings.endGroup();

    mURLCombo->clearEditText();
    mURLCombo->clear();

    berApplet->log( "clear used URLs" );
}

void TSPClientDlg::inputChanged()
{
    QString strInput = mInputText->toPlainText();
    int nLen = getDataLen( mInputTypeCombo->currentText(), strInput );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void TSPClientDlg::requestChanged()
{
    int nLen = mRequestText->toPlainText().length() / 2;
    mRequestLenText->setText( QString("%1").arg( nLen ) );
}

void TSPClientDlg::responseChanged()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ) );
}

void TSPClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void TSPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}


void TSPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void TSPClientDlg::clearResponse()
{
    mResponseText->clear();
}

void TSPClientDlg::findSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 )
    {
        mSrvCertPathText->setText( filePath );
        berApplet->setCurFile(filePath);
    }
}

void TSPClientDlg::viewSrvCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void TSPClientDlg::decodeSrvCert()
{
    BIN binData = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void TSPClientDlg::typeSrvCert()
{
    int nType = -1;
    BIN binData = {0,0};
    BIN binPubInfo = {0,0};
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    JS_PKI_getPubKeyFromCert( &binData, &binPubInfo );

    nType = JS_PKI_getPubKeyType( &binPubInfo );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
    JS_BIN_reset( &binPubInfo );
}


void TSPClientDlg::clickEncode()
{
    int ret = 0;
    BIN binReq = {0,0};
    BIN binInput = {0,0};
    QString strHash = mHashCombo->currentText();
    QString strInput = mInputText->toPlainText();
    QString strPolicy = mPolicyText->text();

    if( strPolicy.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert policy OID" ), this );
        return;
    }

    getBINFromString( &binInput, mInputTypeCombo->currentText(), strInput );

    ret = JS_TSP_encodeRequest( &binInput, strHash.toStdString().c_str(), strPolicy.toStdString().c_str(), &binReq );
    if( ret != 0 )
    {
        berApplet->elog( QString("failed to encode TSP request [%1]").arg( ret ));
        goto end;
    }

    mRequestText->setPlainText( getHexString( &binReq ));

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binInput );
}

void TSPClientDlg::clickSend()
{
    int ret = 0;
    int nStatus = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strReq = mRequestText->toPlainText();
    QString strURL = mURLCombo->currentText();

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert TSP URL"), this );
        goto end;
    }

    if( strReq.length() < 1 )
    {
        berApplet->warningBox( tr("There is no request" ), this );
        goto end;
    }

    getBINFromString( &binReq, DATA_HEX, strReq );

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );
    if( ret == 0 )
    {
        mResponseText->setPlainText( getHexString( &binRsp ));
        setUsedURL( strURL );
    }
    else
    {
        berApplet->warnLog( tr( "fail to send a request to TSP server: %1").arg( ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void TSPClientDlg::clickVerify()
{
    int ret = 0;
    BIN binSrvCert = {0,0};
    BIN binRsp = {0,0};
    BIN binData = {0,0};

    QString strSrvCertPath = mSrvCertPathText->text();
    QString strRspHex = mResponseText->toPlainText();

    JTSTInfo    sTSTInfo;

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    if( strSrvCertPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a TSP server certificate"), this );
        goto end;
    }

    if( strRspHex.length() < 1 )
    {
        berApplet->warningBox( tr("There is no response" ), this );
        goto end;
    }

    JS_BIN_fileReadBER( strSrvCertPath.toLocal8Bit().toStdString().c_str(), &binSrvCert );
    JS_BIN_decodeHex( strRspHex.toStdString().c_str(), &binRsp );

    ret = JS_TSP_verifyResponse( &binRsp, &binSrvCert, &binData, &sTSTInfo );
    if( ret != 0 )
    {
        berApplet->elog( QString( "failed to verify response message [%1]").arg(ret));
        goto end;
    }

    berApplet->messageLog( tr( "verify reponse successfully"), this );

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSrvCert );
    JS_BIN_reset( &binData );
    JS_TSP_resetTSTInfo( &sTSTInfo );
}

void TSPClientDlg::clickTSTInfo()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binTST = {0,0};
    BIN binRsp = {0,0};

    TSTInfoDlg tstInfo;

    QString strOut = mResponseText->toPlainText();
    if( strOut.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no TSP response" ), this );
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        berApplet->warningBox(tr( "failed to decode TSP response"), this );
        goto end;
    }

    tstInfo.setTST( &binTST );
    tstInfo.exec();

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
}
