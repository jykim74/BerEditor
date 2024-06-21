#include <QSettings>

#include "cmp_client_dlg.h"
#include "auth_ref_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "cert_info_dlg.h"
#include "cert_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"
#include "js_error.h"

const QString kCMPUsedURL = "CMPUsedURL";

CMPClientDlg::CMPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGENMBtn, SIGNAL(clicked()), this, SLOT(clickGENM()));
    connect( mIRBtn, SIGNAL(clicked()), this, SLOT(clickIR()));
    connect( mCRBtn, SIGNAL(clicked()), this, SLOT(clickCR()));
    connect( mP10CSRBtn, SIGNAL(clicked()), this, SLOT(clickP10CSR()));
    connect( mSignGENMBtn, SIGNAL(clicked()), this, SLOT(clickSignGENM()));
    connect( mKURBtn, SIGNAL(clicked()), this, SLOT(clickKUR()));
    connect( mRRBtn, SIGNAL(clicked()), this, SLOT(clickRR()));
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

    connect( mRequestText, SIGNAL(textChanged()), this, SLOT(requestChanged()));
    connect( mResponseText, SIGNAL(textChanged()), this, SLOT(responseChanged()));


#if defined( Q_OS_MAC )
    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);

    mPriKeyDecodeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);

    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);

    layout()->setSpacing(5);
#endif

    initialize();
}

CMPClientDlg::~CMPClientDlg()
{

}

void CMPClientDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mURLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    for( int i = 0; i < usedList.size(); i++ )
    {
        QString url = usedList.at(i);
        if( url.length() > 4 ) mURLCombo->addItem( url );
    }

    mURLCombo->setEditable(true);
}

QStringList CMPClientDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kCMPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void CMPClientDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kCMPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kCMPUsedURL, list );
    settings.endGroup();
}

void CMPClientDlg::findCACert()
{
    QString strPath = mCACertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCACertPathText->setText( filePath );
}

void CMPClientDlg::viewCACert()
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

void CMPClientDlg::decodeCACert()
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

void CMPClientDlg::typeCACert()
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


void CMPClientDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void CMPClientDlg::viewCert()
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

void CMPClientDlg::decodeCert()
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

void CMPClientDlg::typeCert()
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


void CMPClientDlg::findPriKey()
{
    QString strPath = mPriKeyPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = berApplet->curFolder();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriKeyPathText->setText( filePath );
}

void CMPClientDlg::decodePriKey()
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

void CMPClientDlg::typePriKey()
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


void CMPClientDlg::clearRequest()
{
    mRequestText->clear();
}

void CMPClientDlg::decodeRequest()
{
    BIN binData = {0,0};
    QString strHex = mRequestText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}


void CMPClientDlg::clearResponse()
{
    mResponseText->clear();
}

void CMPClientDlg::decodeResponse()
{
    BIN binData = {0,0};
    QString strHex = mResponseText->toPlainText();
    JS_BIN_decodeHex( strHex.toStdString().c_str(), &binData );

    berApplet->decodeData( &binData, NULL );

    JS_BIN_reset( &binData );
}

void CMPClientDlg::requestChanged()
{
    int nLen = mRequestText->toPlainText().length() / 2;
    mRequestLenText->setText( QString("%1").arg( nLen ) );
}

void CMPClientDlg::responseChanged()
{
    int nLen = mResponseText->toPlainText().length() / 2;
    mResponseLenText->setText( QString("%1").arg( nLen ) );
}

void CMPClientDlg::clickGENM()
{
    int ret = 0;
    void *pCTX = NULL;

    BIN binCA = {0,0};
    BIN binRef = {0,0};
    BIN binAuth = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();
    JNameValList *pNameValList = NULL;
    JNameValList *pCurList = NULL;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    AuthRefDlg authRef;
    if( authRef.exec() == QDialog::Accepted )
    {
        QString strAuth = authRef.mAuthCodeText->text();
        QString strRef = authRef.mRefNumText->text();

        JS_BIN_decodeHex( strAuth.toStdString().c_str(), &binAuth );
        JS_BIN_decodeHex( strRef.toStdString().c_str(), &binRef );
    }
    else
    {
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execGENMWithSecret( pCTX, &binRef, &binAuth, &pNameValList );
    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec GENM fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "GENM success" ), this );

        pCurList = pNameValList;

        while( pCurList )
        {
            berApplet->log( QString( "Name: %1 Value: %2").arg( pCurList->sNameVal.pName ).arg( pCurList->sNameVal.pValue ));
            pCurList = pCurList->pNext;
        }
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "GENM fail: %1").arg(ret), this );
    }

    JS_BIN_reset(&binCA);
    JS_BIN_reset( &binRef );
    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pNameValList ) JS_UTIL_resetNameValList( &pNameValList );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickIR()
{
    int ret = 0;
    void *pCTX = NULL;

    QString strAuth;
    QString strRef;
    QString strPriHex;
    QString strDN = "CN=TestIR,C=kr";

    BIN binAuth = {0,0};
    BIN binRef = {0,0};
    BIN binNewPri = {0,0};
    BIN binNewCert = {0,0};
    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    AuthRefDlg authRef;
    GenKeyPairDlg genKeyPair;

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );
    if( authRef.exec() != QDialog::Accepted ) goto end;

    strAuth = authRef.mAuthCodeText->text();
    strRef = authRef.mRefNumText->text();

    JS_BIN_decodeHex( strAuth.toStdString().c_str(), &binAuth );
    JS_BIN_decodeHex( strRef.toStdString().c_str(), &binRef );

    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strPriHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binNewPri );

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execIR( pCTX, &binRef, &binAuth, strDN.toStdString().c_str(), &binNewPri, &binNewCert );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec IR fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "IR success" ), this );
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "IR fail: %1").arg(ret), this );
    }

    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binRef );
    JS_BIN_reset( &binNewPri );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickCR()
{
    int ret = 0;
    void *pCTX = NULL;

    QString strAuth;
    QString strRef;
    QString strPriHex;
    QString strDN = "CN=TestCR,C=kr";

    BIN binAuth = {0,0};
    BIN binRef = {0,0};
    BIN binNewPri = {0,0};
    BIN binNewCert = {0,0};
    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    AuthRefDlg authRef;
    GenKeyPairDlg genKeyPair;

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );
    if( authRef.exec() != QDialog::Accepted ) goto end;

    strAuth = authRef.mAuthCodeText->text();
    strRef = authRef.mRefNumText->text();

    JS_BIN_decodeHex( strAuth.toStdString().c_str(), &binAuth );
    JS_BIN_decodeHex( strRef.toStdString().c_str(), &binRef );

    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strPriHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binNewPri );

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execCR( pCTX, &binRef, &binAuth, strDN.toStdString().c_str(), &binNewPri, &binNewCert );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec CR fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "CR success" ), this );
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "CR fail: %1").arg(ret), this );
    }

    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binRef );
    JS_BIN_reset( &binNewPri );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickP10CSR()
{
    int ret = 0;
    void *pCTX = NULL;

    QString strAuth;
    QString strRef;
    QString strPriHex;
    QString strCSRHex;

    BIN binAuth = {0,0};
    BIN binRef = {0,0};
    BIN binNewPri = {0,0};
    BIN binNewCert = {0,0};
    BIN binCSR = {0,0};
    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    AuthRefDlg authRef;
    GenKeyPairDlg genKeyPair;
    MakeCSRDlg makeCSR;

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );
    if( authRef.exec() != QDialog::Accepted ) goto end;

    strAuth = authRef.mAuthCodeText->text();
    strRef = authRef.mRefNumText->text();

    JS_BIN_decodeHex( strAuth.toStdString().c_str(), &binAuth );
    JS_BIN_decodeHex( strRef.toStdString().c_str(), &binRef );

    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strPriHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binNewPri );

    makeCSR.setPriKey( &binNewPri );
    if( makeCSR.exec() != QDialog::Accepted ) goto end;

    strCSRHex = makeCSR.getCSRHex();
    JS_BIN_decodeHex( strCSRHex.toStdString().c_str(), &binCSR );

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execP10CSR( pCTX, &binRef, &binAuth, &binCSR, &binNewCert );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec P10CSR fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "P10CSR success" ), this );
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "CR fail: %1").arg(ret), this );
    }

    JS_BIN_reset( &binAuth );
    JS_BIN_reset( &binRef );
    JS_BIN_reset( &binNewPri );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickSignGENM()
{
    int ret = 0;
    void *pCTX = NULL;

    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    BIN binPri = {0,0};
    BIN binCert = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    JNameValList *pNameValList = NULL;
    JNameValList *pCurList = NULL;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );

    if( mCertGroup->isChecked() == true )
    {
        QString strCert = mCertPathText->text();

        if( strCert.length() < 1 )
        {
            berApplet->warningBox( tr( "find a certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strCert.toLocal8Bit().toStdString().c_str(), &binCert );
        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
    }

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execGENMWithSign( pCTX, &binPri, &binCert, &pNameValList );
    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec GENM fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "GENM success" ), this );

        pCurList = pNameValList;

        while( pCurList )
        {
            berApplet->log( QString( "Name: %1 Value: %2").arg( pCurList->sNameVal.pName ).arg( pCurList->sNameVal.pValue ));
            pCurList = pCurList->pNext;
        }
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "GENM fail: %1").arg(ret), this );
    }

    JS_BIN_reset(&binCA);
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pNameValList ) JS_UTIL_resetNameValList( &pNameValList );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickKUR()
{
    int ret = 0;
    void *pCTX = NULL;

    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binNewPri = {0,0};
    BIN binNewCert = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    QString strPriHex;

    GenKeyPairDlg genKeyPair;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );

    if( genKeyPair.exec() != QDialog::Accepted ) goto end;

    strPriHex = genKeyPair.getPriKeyHex();
    JS_BIN_decodeHex( strPriHex.toStdString().c_str(), &binNewPri );

    if( mCertGroup->isChecked() )
    {
        QString strCert = mCertPathText->text();
        if( strCert.length() < 1 )
        {
            berApplet->warningBox( tr( "find a certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strCert.toLocal8Bit().toStdString().c_str(), &binCert );

        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
    }

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execKUR( pCTX, &binPri, &binCert, &binNewPri, &binNewCert );
    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec KUR fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "KUR success" ), this );
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "KUR fail: %1").arg(ret), this );
    }

    JS_BIN_reset(&binCA);
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickRR()
{
    int ret = 0;
    void *pCTX = NULL;
    int nReason = 0;

    BIN binCA = {0,0};

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    BIN binPri = {0,0};
    BIN binCert = {0,0};

    QString strURL = mURLCombo->currentText();
    QString strCACert = mCACertPathText->text();


    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter CMP URL"), this );
        return;
    }

    if( strCACert.length() < 1 )
    {
        berApplet->warningBox( tr( "find a CA certificate" ), this );
        return;
    }

    JS_BIN_fileReadBER( strCACert.toLocal8Bit().toStdString().c_str(), &binCA );

    if( mCertGroup->isChecked() == true )
    {
        QString strCert = mCertPathText->text();
        if( strCert.length() < 1 )
        {
            berApplet->warningBox( tr( "find a certificate" ), this );
            return;
        }

        JS_BIN_fileReadBER( strCert.toLocal8Bit().toStdString().c_str(), &binCert );

        ret = readPrivateKey( &binPri );
        if( ret != 0 ) goto end;
    }
    else
    {
        CertManDlg certMan;
        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a certificate") );

        if( certMan.exec() != QDialog::Accepted )
            goto end;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
    }

    ret = JS_CMP_init( strURL.toStdString().c_str(), &binCA, &pCTX );
    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP init fail: %1").arg(ret ));
        goto end;
    }

    ret = JS_CMP_execRR( pCTX, &binPri, &binCert, nReason );
    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    mRequestText->setPlainText( getHexString( &binReq ) );
    mResponseText->setPlainText( getHexString( &binRsp ));

    if( ret != 0 )
    {
        berApplet->elog( QString( "CMP exec RR fail: %1").arg(ret ));
        goto end;
    }

    JS_CMP_getReqRsp( pCTX, &binReq, &binRsp );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "RR success" ), this );
    }

end :
    setUsedURL( strURL );
    if( ret != 0 )
    {
        berApplet->warnLog( tr( "RR fail: %1").arg(ret), this );
    }

    JS_BIN_reset(&binCA);
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pCTX ) JS_CMP_final( pCTX );
}

void CMPClientDlg::clickClearAll()
{
    clearRequest();
    clearResponse();
}

int CMPClientDlg::readPrivateKey( BIN *pPriKey )
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
