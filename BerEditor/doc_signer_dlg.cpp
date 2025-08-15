#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamReader>
#include <QFileInfo>

#include "doc_signer_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "common.h"
#include "acme_tree_dlg.h"
#include "acme_object.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "key_list_dlg.h"
#include "pdf_sign.h"
#include "cms_info_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"
#include "js_pki_xml.h"
#include "js_pkcs7.h"
#include "js_error.h"
#include "js_tsp.h"
#include "js_http.h"

const QString kTSPUsedURL = "TSPUsedURL";

DocSignerDlg::DocSignerDlg(QWidget *parent)
    : QDialog(parent)
{
    memset( &cms_, 0x00, sizeof(BIN));

    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mFindSrcPathBtn, SIGNAL(clicked()), this, SLOT(findSrcPath()));
    connect( mFindDstPathBtn, SIGNAL(clicked()), this, SLOT(findDstPath()));

    connect( mTabSigner, SIGNAL(currentChanged(int)), this, SLOT(changeSignerTab()));

    connect( mCMSDataText, SIGNAL(textChanged()), this, SLOT(changeCMSData()));
    connect( mCMSAuthCheck, SIGNAL(clicked()), this, SLOT(checkCMSAuth()));
    connect( mCMSMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickCMSMakeSign()));
    connect( mCMSVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickCMSVerifySign()));

    connect( mJSONPayloadText, SIGNAL(textChanged()), this, SLOT(changeJSON_Payload()));
    connect( mJSON_JWSText, SIGNAL(textChanged()), this, SLOT(changeJSON_JWS()));

    connect( mJSONComputeSignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_ComputeSignature()));
    connect( mJSONVerifySignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_VerifySignature()));
    connect( mJSONPayloadClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadClear()));
    connect( mJSONPayloadViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadView()));
    connect( mJSON_JWSClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSClear()));
    connect( mJSON_JWSViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSView()));

    connect( mXMLMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickXML_MakeSign()));
    connect( mXMLMakeSign2Btn, SIGNAL(clicked()), this, SLOT(clickXML_MakeSign2()));
    connect( mXMLEncryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt()));
    connect( mXMLEncrypt2Btn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt2()));
    connect( mXMLVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickXML_VerifySign()));
    connect( mXMLDecryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Decrypt()));

    connect( mXMLBodyClearBtn, SIGNAL(clicked()), this, SLOT(clickXML_BodyClear()));
    connect( mXMLSignClearBtn, SIGNAL(clicked()), this, SLOT(clickXML_SignClear()));

    connect( mXMLBodyText, SIGNAL(textChanged()), this, SLOT(changeXML_Body()));
    connect( mXMLSignText, SIGNAL(textChanged()), this, SLOT(changeXML_Sign()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCMSClearBtn->setFixedWidth(34);
    mCMS_TSPGroup->layout()->setMargin(5);
    mCMS_TSPGroup->layout()->setSpacing(5);

    mJSONPayloadClearBtn->setFixedWidth(34);
    mJSONPayloadViewBtn->setFixedWidth(34);
    mJSON_JWSClearBtn->setFixedWidth(34);
    mJSON_JWSViewBtn->setFixedWidth(34);

    mXMLBodyClearBtn->setFixedWidth(34);
    mXMLSignClearBtn->setFixedWidth(34);

    mTabJSON->layout()->setSpacing(5);
    mTabJSON->layout()->setMargin(5);

    mTabXML->layout()->setSpacing(5);
    mTabXML->layout()->setMargin(5);

    mTabCMS->layout()->setSpacing(5);
    mTabCMS->layout()->setMargin(5);
#endif


    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

DocSignerDlg::~DocSignerDlg()
{
    JS_BIN_reset( &cms_ );
}

void DocSignerDlg::clickClearAll()
{
    mSrcPathText->clear();
    mDstPathText->clear();
    mJSONPayloadText->clear();
    mJSON_JWSText->clear();
    mXMLBodyText->clear();
    mXMLSignText->clear();
}

void DocSignerDlg::changeSignerTab()
{
    int index = mTabSigner->currentIndex();

    if( index == 0 )
        mUseCertManCheck->setEnabled( false );
    else
        mUseCertManCheck->setEnabled( true );
}

void DocSignerDlg::findSrcPath()
{
    QString strPath = mSrcPathText->text();
    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_XML, strPath );

    if( strFileName.length() < 1 ) return;

    JS_BIN_reset( &cms_ );

    mSrcPathText->setText( strFileName );

}

void DocSignerDlg::findDstPath()
{
    QString strPath = mDstPathText->text();
    QString strFileName = berApplet->findSaveFile( this, JS_FILE_TYPE_XML, strPath );

    if( strFileName.length() < 1 ) return;

    mDstPathText->setText( strFileName );
}

void DocSignerDlg::checkCMSAuth()
{
    bool bVal = mCMSAuthCheck->isChecked();

    mCMSUserLabel->setEnabled( bVal );
    mCMSUserText->setEnabled( bVal );
    mCMSPasswdLabel->setEnabled( bVal );
    mCMSPasswdText->setEnabled( bVal );
}

void DocSignerDlg::changeCMSData()
{
    QString strData = mCMSDataText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strData );
    mCMSDataLenText->setText( strLen );
}

void DocSignerDlg::clickCMSClear()
{
    mCMSDataText->clear();
}

void DocSignerDlg::clickCMSView()
{
    int ret = 0;
    BIN binSrc = {0,0};
    CMSInfoDlg cmsInfo;

    if( cms_.nLen > 0 )
        JS_BIN_copy( &binSrc, &cms_ );
    else
    {
        QString strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source xml" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }

    ret = JS_PKCS7_getType( &binSrc );
    if( ret < 0 )
    {
        berApplet->warningBox( tr( "This is not a CMS message" ), this );
        goto end;
    }

    cmsInfo.setCMS( &binSrc );
    cmsInfo.exec();

end :
    JS_BIN_reset( &binSrc );
}

void DocSignerDlg::initUI()
{
    mHashCombo->addItems( kSHAHashList );
    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mTabSigner->setCurrentIndex(0);
}

void DocSignerDlg::initialize()
{
    mCMS_URLCombo->setEditable( true );
    QStringList usedList = getUsedURL();
    mCMS_URLCombo->addItems( usedList );

    mCMSPolicyText->setPlaceholderText( "1.2.3.4" );

    checkCMSAuth();
    changeSignerTab();
}

QStringList DocSignerDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void DocSignerDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTSPUsedURL, list );
    settings.endGroup();

    mCMS_URLCombo->clear();
    mCMS_URLCombo->addItems( list );
}

int DocSignerDlg::getPubKey( BIN *pPubKey )
{
    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        CertManDlg certMan;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return -1;

        certMan.getCert( &binCert );
        JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );
    }
    else
    {
        QString strPubPath;
        QString strPriPath;

        KeyPairManDlg keyPairMan;
        keyPairMan.setTitle( tr( "Select keypair" ));
        keyPairMan.setMode( KeyPairModeSelect );

        if( keyPairMan.exec() != QDialog::Accepted )
            return -1;

        strPubPath = keyPairMan.getPubPath();
        strPriPath = keyPairMan.getPriPath();

        JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), pPubKey );
    }

    return 0;
}

int DocSignerDlg::getCert( BIN *pCert )
{
    JCertInfo sCertInfo;
    CertManDlg certMan;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getCert( pCert );
    JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

int DocSignerDlg::getPriKey( BIN *pPriKey )
{
    if( mUseCertManCheck->isChecked() == true )
    {
        CertManDlg certMan;

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return -1;

        certMan.getPriKey( pPriKey );
    }
    else
    {
        QString strPubPath;
        QString strPriPath;

        KeyPairManDlg keyPairMan;
        keyPairMan.setTitle( tr( "Select keypair" ));
        keyPairMan.setMode( KeyPairModeSelect );

        if( keyPairMan.exec() != QDialog::Accepted )
            return -1;

        strPubPath = keyPairMan.getPubPath();
        strPriPath = keyPairMan.getPriPath();

        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pPriKey );
    }

    return 0;
}

int DocSignerDlg::getKeyPair( BIN *pPubKey, BIN *pPriKey )
{
    QString strName;

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        CertManDlg certMan;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return -1;

        certMan.getPriKey( pPriKey );
        certMan.getCert( &binCert );
        JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        strName = sCertInfo.pSubjectName;
        JS_PKI_getPubKeyFromCert( &binCert, pPubKey );
        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCertInfo );
    }
    else
    {
        QString strPubPath;
        QString strPriPath;

        KeyPairManDlg keyPairMan;
        keyPairMan.setTitle( tr( "Select keypair" ));
        keyPairMan.setMode( KeyPairModeSelect );

        if( keyPairMan.exec() != QDialog::Accepted )
            return -1;

        strPubPath = keyPairMan.getPubPath();
        strPriPath = keyPairMan.getPriPath();
        strName = keyPairMan.getName();

        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), pPriKey );
        JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), pPubKey );
    }

    return 0;
}

int DocSignerDlg::getPriKeyCert( BIN *pPriKey, BIN *pCert )
{
    QString strName;
    JCertInfo sCertInfo;
    CertManDlg certMan;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a sign certificate" ));

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getPriKey( pPriKey );
    certMan.getCert( pCert );
    strName = sCertInfo.pSubjectName;

    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

int DocSignerDlg::getTSP( const BIN *pSrc, BIN *pTSP )
{
    int ret = 0;
    int nUseNonce = 0;
    QString strHash = mHashCombo->currentText();
    QString strPolicy = mCMSPolicyText->text();
    const char *pPolicy = NULL;
    QString strURL = mCMS_URLCombo->currentText();

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strAuth;
    int nStatus = -1;
    BIN binTST = {0,0};

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert TSP URL"), this );
        mCMS_URLCombo->setFocus();
        ret = -1;
        goto end;
    }

    if( mCMSAuthCheck->isChecked() == true )
    {
        QString strUser = mCMSUserText->text();
        QString strPass = mCMSPasswdText->text();
        QString strUP;
        BIN bin = {0,0};
        char *pBase64 = NULL;

        if( strUser.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a username" ), this );
            mCMSUserText->setFocus();
            ret = -1;
            goto end;
        }

        if( strPass.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mCMSPasswdText->setFocus();
            ret = -1;
            goto end;
        }

        strUP = QString( "%1:%2" ).arg( strUser ).arg( strPass );
        JS_BIN_set( &bin, (unsigned char *)strUP.toStdString().c_str(), strUP.length() );
        JS_BIN_encodeBase64( &bin, &pBase64 );
        strAuth = QString( "Basic %1").arg( pBase64 );

        JS_BIN_reset( &bin );
        if( pBase64 ) JS_free( pBase64 );
    }

    if( mCMSUseNonceCheck->isChecked() == true )
        nUseNonce = 1;

    if( strPolicy.length() > 0 ) pPolicy = strPolicy.toStdString().c_str();

    ret = JS_TSP_encodeRequest( pSrc, strHash.toStdString().c_str(), pPolicy, nUseNonce, &binReq );
    if( ret != 0 ) goto end;

    if( mCMSAuthCheck->isChecked() == true )
        ret = JS_HTTP_requestAuthPostBin( strURL.toStdString().c_str(), "application/tsp-request", strAuth.toStdString().c_str(), &binReq, &nStatus, &binRsp );
    else
        ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );

    if( ret != 0 ) goto end;

    ret = JS_TSP_decodeResponse( &binRsp, pTSP, &binTST );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binTST );

    return ret;
}

void DocSignerDlg::clickCMSMakeSign()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binTSP = {0,0};
    BIN binSigned = {0,0};

    QString strHash = mHashCombo->currentText();

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = getPriKeyCert( &binPri, &binCert );
    if( ret != 0 ) goto end;

    JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );

    if( mCMS_TSPGroup->isChecked() == true )
    {
        ret = getTSP( &binSrc, &binTSP );
        if( ret != 0 ) goto end;
    }

    ret = JS_PKCS7_makeSignedDataWithTSP( strHash.toStdString().c_str(),
                                         &binSrc,
                                         &binPri,
                                         &binCert,
                                         &binTSP,
                                         &binSigned );


    if( ret == 0 )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binSigned );

        QString strDstPath = mDstPathText->text();

        if( strDstPath.length() < 1 )
        {
            QFileInfo fileInfo( strSrcPath );

            strDstPath = QString( "%1/%2_dst.%3" )
                             .arg( fileInfo.path() )
                             .arg( fileInfo.baseName() )
                             .arg( "cms" );

            mDstPathText->setText( strDstPath );
        }

        JS_BIN_fileWrite( &binSigned, strDstPath.toLocal8Bit().toStdString().c_str() );
        berApplet->messageBox( tr( "The CMS file[%1] has been saved." ).arg( strDstPath ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binTSP );
    JS_BIN_reset( &binSigned );
}

void DocSignerDlg::clickCMSVerifySign()
{
    int ret = 0;
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binData = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = getCert( &binCert );
    if( ret != 0 ) goto end;

    JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );

    ret = JS_PKCS7_getType( &binSrc );
    if( ret != JS_PKCS7_TYPE_SIGNED )
    {
        berApplet->warningBox( tr("This is not a Signed Data CMS message:%1").arg(ret), this );
        goto end;
    }

    ret = JS_PKCS7_verifySignedData( &binSrc, &binCert, &binData );

    mCMSDataText->setPlainText( getHexString( &binData ));

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr( "Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to verify: %1").arg( ret ), this );
    }

end:
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binData );
}

void DocSignerDlg::clickJSON_ComputeSignature()
{
    int ret = 0;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    QString strName;
    int nKeyType = -1;


    ACMEObject objJson;
    QJsonObject objJWK;
    QJsonObject objProtected;

    QString strAlg;
    QString strHash = mHashCombo->currentText();
    QString strPayload = mJSONPayloadText->toPlainText();

    if( strPayload.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a payload" ), this );
        mJSONPayloadText->setFocus();
        return;
    }

    ret = getKeyPair( &binPub, &binPri );

    objJson.setPayload( strPayload );
    nKeyType = JS_PKI_getPriKeyType( &binPri );
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &binPub, strHash, strName );
    objProtected = ACMEObject::getJWKProtected( strAlg, objJWK, "", "" );
    objJson.setProtected( objProtected );
    objJson.setSignature( &binPri, strHash );

    mJSON_JWSText->setPlainText( objJson.getPacketJson() );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void DocSignerDlg::clickJSON_VerifySignature()
{
    int ret = 0;
    BIN binPub = {0,0};
    QString strJWS = mJSON_JWSText->toPlainText();

    if( strJWS.length() < 1 )
    {
        berApplet->warningBox( tr("There is no JWS" ), this );
        return;
    }

    ret = getPubKey( &binPub );

    ACMEObject acmeObj;
    acmeObj.setObjectFromJson( strJWS );

    ret = acmeObj.verifySignature( &binPub );
    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr("Verify fail: %1").arg( ret ), this );

    JS_BIN_reset( &binPub );
}

void DocSignerDlg::clickJSON_PayloadClear()
{
    mJSONPayloadText->clear();
}

void DocSignerDlg::clickJSON_JWSClear()
{
    mJSON_JWSText->clear();
}

void DocSignerDlg::clickJSON_PayloadView()
{

}

void DocSignerDlg::clickJSON_JWSView()
{

}

void DocSignerDlg::changeJSON_Payload()
{
    QString strPayload = mJSONPayloadText->toPlainText();
    mJSONPayloadLenText->setText( QString("%1").arg( strPayload.length() ));
}

void DocSignerDlg::changeJSON_JWS()
{
    QString strJWS = mJSON_JWSText->toPlainText();
    mJSON_JWSLenText->setText( QString("%1").arg( strJWS.length() ));
}

void DocSignerDlg::clickXML_BodyClear()
{
    mXMLBodyText->clear();
}

void DocSignerDlg::clickXML_SignClear()
{
    mXMLSignText->clear();
}

void DocSignerDlg::clickXML_MakeSign()
{
    int ret = 0;
    BIN binPri = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strDstPath = mDstPathText->text();
    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );

        strDstPath = QString( "%1/%2_dst.%3" )
                         .arg( fileInfo.path() )
                         .arg( fileInfo.baseName() )
                         .arg( "xml" );

        mDstPathText->setText( strDstPath );
    }

    ret = getPriKey( &binPri );

    JS_XML_init();

    ret = JS_XML_signWithInfo( strSrcPath.toLocal8Bit().toStdString().c_str(),
                    &binPri,
                    strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to make signature: %1").arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr("XML Signature OK" ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binPri );

    return;
}

void DocSignerDlg::clickXML_MakeSign2()
{
    int ret = 0;
    BIN binPri = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strDstPath = mDstPathText->text();
    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );

        strDstPath = QString( "%1/%2_dst.%3" )
                         .arg( fileInfo.path() )
                         .arg( fileInfo.baseName() )
                         .arg( "xml" );

        mDstPathText->setText( strDstPath );
    }

    ret = getPriKey( &binPri );

    JS_XML_init();

    ret = JS_XML_signDoc( strSrcPath.toLocal8Bit().toStdString().c_str(),
                              &binPri,
                              strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to make signature: %1").arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr("XML Signature OK" ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binPri );

    return;
}

void DocSignerDlg::clickXML_Encrypt()
{
    int ret = 0;
    BIN binBody = {0,0};
    BIN binKey = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strDstPath = mDstPathText->text();
    if( strDstPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a destination xml" ), this );
        mDstPathText->setFocus();
        return;
    }

    QString strBody = mXMLBodyText->toPlainText();
    if( strBody.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a body" ), this );
        mXMLBodyText->setFocus();
        return;
    }

    KeyListDlg keyList;
    keyList.setTitle( tr( "Select key" ));
    keyList.setManage(false);

    if( keyList.exec() != QDialog::Accepted )
        return;

    QString strKey = keyList.getKey();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );

    getBINFromString( &binBody, DATA_STRING, strBody );

    JS_XML_init();

    ret = JS_XML_encryptWithInfo(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        &binKey,
        &binBody,
        strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to encrypt: %1").arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr("XML Encrypt OK" ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binBody );
    JS_BIN_reset( &binKey );

    return;
}

void DocSignerDlg::clickXML_Encrypt2()
{
    int ret = 0;
    BIN binKey = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strDstPath = mDstPathText->text();
    if( strDstPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a destination xml" ), this );
        mDstPathText->setFocus();
        return;
    }

    KeyListDlg keyList;
    keyList.setTitle( tr( "Select key" ));
    keyList.setManage(false);

    if( keyList.exec() != QDialog::Accepted )
        return;

    QString strKey = keyList.getKey();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );

    JS_XML_init();

    ret = JS_XML_encrypt(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        &binKey,
        strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to encrypt: %1").arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr("XML Encrypt OK" ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binKey );

    return;
}

void DocSignerDlg::clickXML_VerifySign()
{
    int ret = 0;
    BIN binPub = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    ret = getPubKey( &binPub );
    if( ret != 0 ) goto end;

    JS_XML_init();

    ret = JS_XML_verify( strSrcPath.toLocal8Bit().toStdString().c_str(), &binPub );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr("XML Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to verify: %1").arg( ret ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binPub );

    return;
}

void DocSignerDlg::clickXML_Decrypt()
{
    int ret = 0;
    BIN binKey = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( strSrcPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a source xml" ), this );
        mSrcPathText->setFocus();
        return;
    }

    QString strDstPath = mDstPathText->text();
    if( strDstPath.length() < 1 )
    {
        berApplet->warningBox( tr( "find a destination xml" ), this );
        mDstPathText->setFocus();
        return;
    }

    KeyListDlg keyList;
    keyList.setTitle( tr( "Select key" ));
    keyList.setManage(false);

    if( keyList.exec() != QDialog::Accepted )
        return;

    QString strKey = keyList.getKey();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );

    JS_XML_init();

    ret = JS_XML_decrypt(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        &binKey,
        strDstPath.toLocal8Bit().toStdString().c_str() );

    if( ret < 0 )
    {
        berApplet->warningBox( tr( "fail to decrypt: %1").arg( ret ), this );
    }
    else
    {
        berApplet->messageBox( tr("XML Decrypt OK [%1]" ).arg( strDstPath ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binKey );
}

void DocSignerDlg::changeXML_Body()
{
    QString strBody = mXMLBodyText->toPlainText();
    mXMLBodyLenText->setText( QString("%1").arg( strBody.length() ));
}

void DocSignerDlg::changeXML_Sign()
{
    QString strSign = mXMLSignText->toPlainText();
    mXMLSignLenText->setText( QString("%1").arg( strSign.length() ));
}
