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

const QString kTSPUsedURL = "TSPUsedURL";

TSPClientDlg::TSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
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
    if( filePath.length() > 0 ) mSrvCertPathText->setText( filePath );
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
    QString strFile = mSrvCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a server certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}


void TSPClientDlg::clickEncode()
{

}

void TSPClientDlg::clickSend()
{

}

void TSPClientDlg::clickVerify()
{

}

void TSPClientDlg::clickTSTInfo()
{
    TSTInfoDlg tstInfo;
    tstInfo.exec();
}
