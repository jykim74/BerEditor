#include <QSettings>

#include "ocsp_client_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_info_dlg.h"

#include "js_bin.h"
#include "js_pki.h"

const QString kOCSPUsedURL = "OCSPUsedURL";

OCSPClientDlg::OCSPClientDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindSignCertBtn, SIGNAL(clicked()), this, SLOT(findSignCert()));
    connect( mFindSignPriKeyBtn, SIGNAL(clicked()), this, SLOT(findSignPriKey()));
    connect( mFindSrvCertBtn, SIGNAL(clicked()), this, SLOT(findSrvCert()));

    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));
    connect( mSignCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignCert()));
    connect( mSignPriKeyTypeBtn, SIGNAL(clicked()), this, SLOT(typeSignPriKey()));
    connect( mSrvCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeSrvCert()));

    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(viewCert()));
    connect( mSignCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSignCert()));
    connect( mSrvCertViewBtn, SIGNAL(clicked()), this, SLOT(viewSrvCert()));

    connect( mCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeCert()));
    connect( mSignCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSignCert()));
    connect( mSignPriKeyDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSignPriKey()));
    connect( mSrvCertDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeSrvCert()));
    connect( mRequestDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeRequest()));
    connect( mResponseDecodeBtn, SIGNAL(clicked()), this, SLOT(decodeResponse()));

    connect( mRequestClearBtn, SIGNAL(clicked()), this, SLOT(clearRequest()));
    connect( mResponseClearBtn, SIGNAL(clicked()), this, SLOT(clearResponse()));

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(clickEncode()));
    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mVerifyBtn, SIGNAL(clicked()), this, SLOT(clickVerify()));

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));
}

OCSPClientDlg::~OCSPClientDlg()
{

}

void OCSPClientDlg::initialize()
{
    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }
}

QStringList OCSPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kOCSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void OCSPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kOCSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kOCSPUsedURL, list );
    settings.endGroup();
}


void OCSPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void OCSPClientDlg::findSignCert()
{
    QString strPath = mSignCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mSignCertPathText->setText( filePath );
}

void OCSPClientDlg::findSignPriKey()
{
    QString strPath = mSignPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mSignPriKeyPathText->setText( filePath );
}

void OCSPClientDlg::findSrvCert()
{
    QString strPath = mSrvCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mSrvCertPathText->setText( filePath );
}

void OCSPClientDlg::typeCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeSignCert()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );
    nType = JS_PKI_getPriKeyType( &binData );
    berApplet->messageBox( tr( "The certificate type is %1").arg( getKeyTypeName( nType )), this);


    JS_BIN_reset( &binData );
}

void OCSPClientDlg::typeSignPriKey()
{
    int nType = -1;
    BIN binData = {0,0};
    QString strFile = mSignPriKeyPathText->text();

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

void OCSPClientDlg::typeSrvCert()
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


void OCSPClientDlg::viewCert()
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

void OCSPClientDlg::viewSignCert()
{
    CertInfoDlg certInfo;

    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    certInfo.setCertBIN( &binData );
    certInfo.exec();

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::viewSrvCert()
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


void OCSPClientDlg::decodeCert()
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

void OCSPClientDlg::decodeSignCert()
{
    BIN binData = {0,0};
    QString strFile = mSignCertPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeSignPriKey()
{
    BIN binData = {0,0};
    QString strFile = mSignPriKeyPathText->text();

    if( strFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find a sign private key" ), this );
        return;
    }

    JS_BIN_fileReadBER( strFile.toLocal8Bit().toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, strFile );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeSrvCert()
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

void OCSPClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void OCSPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}


void OCSPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void OCSPClientDlg::clearResponse()
{
    mResponseText->clear();
}


void OCSPClientDlg::clickEncode()
{

}

void OCSPClientDlg::clickSend()
{

}

void OCSPClientDlg::clickVerify()
{

}

void OCSPClientDlg::requestChanged()
{
    int nLen = mRequestText->toPlainText().length() / 2;
    mRequestLenText->setText( QString("%1").arg( nLen ) );
}

void OCSPClientDlg::responseChanged()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ) );
}
