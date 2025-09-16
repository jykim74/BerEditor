#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamReader>
#include <QFileInfo>
#include <QDateTime>

#include "doc_signer_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "common.h"
#include "json_tree_dlg.h"
#include "acme_object.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "key_list_dlg.h"
#include "cms_info_dlg.h"
#include "time_stamp_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"
#include "js_pki_xml.h"
#include "js_pkcs7.h"
#include "js_cms.h"
#include "js_error.h"
#include "js_tsp.h"
#include "js_http.h"

const QString kTSPUsedURL = "TSPUsedURL";

static const QStringList kCipherList = { "aes-128-cbc", "aes-192-cbc", "aes-256-cbc" };


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

    connect( mSrcFileCheck, SIGNAL(clicked()), this, SLOT(checkSrcFile()));
    connect( mDstFileCheck, SIGNAL(clicked()), this, SLOT(checkDstFile()));

    connect( mTabSigner, SIGNAL(currentChanged(int)), this, SLOT(changeSignerTab()));
    connect( mUseTSPCheck, SIGNAL(clicked()), this, SLOT(checkUseTSP()));
    connect( mTSPBtn, SIGNAL(clicked()), this, SLOT(clickTSP()));

    connect( mCMSEncodeRadio, SIGNAL(clicked()), this, SLOT(checkCMSEncode()));
    connect( mCMSDecodeRadio, SIGNAL(clicked()), this, SLOT(checkCMSDecode()));
    connect( mCMSAutoDetectCheck, SIGNAL(clicked()), this, SLOT(checkCMSAutoDetect()));

    connect( mCMSCmdCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeCMSCmd()));
    connect( mCMSRunBtn, SIGNAL(clicked(bool)), this, SLOT(clickCMSRun()));

    connect( mCMSClearBtn, SIGNAL(clicked()), this, SLOT(clickCMSClear()));
    connect( mCMSDataText, SIGNAL(textChanged()), this, SLOT(changeCMSData()));
    connect( mCMSOutputText, SIGNAL(textChanged()), this, SLOT(changeCMSOutput()));

    connect( mCMSDataViewBtn, SIGNAL(clicked()), this, SLOT(clickCMSDataView()));
    connect( mCMSViewBtn, SIGNAL(clicked()), this, SLOT(clickCMSView()));
    connect( mCMSOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickCMSOutputClear()));
    connect( mCMSOutputUpBtn, SIGNAL(clicked()), this, SLOT(clickCMSOutputUp()));
    connect( mCMSOutputDecodeBtn, SIGNAL(clicked()), this, SLOT(clickCMSOutputDecode()));

    connect( mJSONPayloadText, SIGNAL(textChanged()), this, SLOT(changeJSON_Payload()));
    connect( mJSON_JWSText, SIGNAL(textChanged()), this, SLOT(changeJSON_JWS()));
    connect( mJSON_JWSUpBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSUp()));

    connect( mJSONComputeSignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_ComputeSignature()));
    connect( mJSONVerifySignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_VerifySignature()));
    connect( mJSONPayloadClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadClear()));
    connect( mJSONPayloadViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadView()));
    connect( mJSON_JWSClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSClear()));
    connect( mJSON_JWSViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSView()));

    connect( mXMLTemplateCheck, SIGNAL(clicked()), this, SLOT(checkXML_UseTemplate()));
    connect( mXMLMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickXML_MakeSign()));
    connect( mXMLEncryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt()));
    connect( mXMLVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickXML_VerifySign()));
    connect( mXMLDecryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Decrypt()));

    connect( mXMLBodyClearBtn, SIGNAL(clicked()), this, SLOT(clickXML_BodyClear()));
    connect( mXMLBodyText, SIGNAL(textChanged()), this, SLOT(changeXML_Body()));
    connect( mXMLDataText, SIGNAL(textChanged(QString)), this, SLOT(changeXML_Data()));
    connect( mXMLResClearBtn, SIGNAL(clicked()), this, SLOT(clickXML_ResClear()));
    connect( mXMLResUpBtn, SIGNAL(clicked()), this, SLOT(clickXML_ResUp()));



#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mCMSDataViewBtn->setFixedWidth(34);
    mCMSViewBtn->setFixedWidth(34);

    mCMSClearBtn->setFixedWidth(34);
    mCMSOutputClearBtn->setFixedWidth(34);
    mCMSOutputDecodeBtn->setFixedWidth(34);

    mJSONPayloadClearBtn->setFixedWidth(34);
    mJSONPayloadViewBtn->setFixedWidth(34);
    mJSON_JWSClearBtn->setFixedWidth(34);
    mJSON_JWSViewBtn->setFixedWidth(34);

    mXMLBodyClearBtn->setFixedWidth(34);
    mXMLResClearBtn->setFixedWidth(34);

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
    mCMSDataText->clear();
    mCMSCmdNameText->clear();
    mCMSOutputText->clear();
    mJSONPayloadText->clear();
    mJSON_JWSText->clear();
    mXMLBodyText->clear();
    mXMLDataText->clear();
    mXMLResText->clear();
}

void DocSignerDlg::checkCMSEncode()
{
    mCMSCmdCombo->clear();

    mCMSCmdCombo->setEnabled( true );
    mCMSCmdCombo->addItems( kCMSEncodeList );

    mCMSAutoDetectCheck->setEnabled(false);
    mCMSRunBtn->setText( tr( "Encode" ));
}

void DocSignerDlg::checkCMSDecode()
{
    mCMSCmdCombo->clear();

    mCMSCmdCombo->addItems( kCMSDecodeList );
    mCMSAutoDetectCheck->setEnabled( true );
    bool bVal = mCMSAutoDetectCheck->isChecked();

    mCMSCmdCombo->setEnabled( !bVal );
    mCMSRunBtn->setText( tr("Decode" ));
}

void DocSignerDlg::checkCMSAutoDetect()
{
    bool bVal = mCMSAutoDetectCheck->isChecked();

    mCMSCmdCombo->setEnabled( !bVal );
}

void DocSignerDlg::changeSignerTab()
{
    int index = mTabSigner->currentIndex();

    if( index == 0 )
    {
        mUseCertManCheck->setEnabled( false );
        mXMLTemplateCheck->setEnabled( false );
    }
    else if( index == 1 )
    {
        mUseCertManCheck->setEnabled( true );
        mXMLTemplateCheck->setEnabled( false );
    }
    else
    {
        mUseCertManCheck->setEnabled( true );
        mXMLTemplateCheck->setEnabled( true );
    }
}

void DocSignerDlg::checkSrcFile()
{
    bool bVal = mSrcFileCheck->isChecked();

    mSrcPathText->setEnabled( bVal );
    mFindSrcPathBtn->setEnabled( bVal );

    mCMSDataText->setEnabled( !bVal );
    mCMSDataLenText->setEnabled( !bVal );

    mJSONPayloadText->setEnabled( !bVal );
    mJSONPayloadLenText->setEnabled( !bVal );

    mXMLBodyText->setEnabled( !bVal );
    mXMLBodyLenText->setEnabled( !bVal );
}

void DocSignerDlg::checkDstFile()
{
    bool bVal = mDstFileCheck->isChecked();

    mDstPathText->setEnabled( bVal );
    mFindDstPathBtn->setEnabled( bVal );
}

void DocSignerDlg::findSrcPath()
{
    int index = mTabSigner->currentIndex();
    int nType = JS_FILE_TYPE_PKCS7;

    if( index == 1 )
        nType = JS_FILE_TYPE_JSON;
    else if( index == 2 )
        nType = JS_FILE_TYPE_XML;

    QString strPath = mSrcPathText->text();
    QString strFileName = berApplet->findFile( this, nType, strPath );

    if( strFileName.length() < 1 ) return;

    JS_BIN_reset( &cms_ );

    mSrcPathText->setText( strFileName );
}

void DocSignerDlg::findDstPath()
{
    int index = mTabSigner->currentIndex();
    int nType = JS_FILE_TYPE_PKCS7;

    if( index == 1 )
        nType = JS_FILE_TYPE_JSON;
    else if( index == 2 )
        nType = JS_FILE_TYPE_XML;

    QString strPath = mDstPathText->text();
    QString strFileName = berApplet->findSaveFile( this, nType, strPath );

    if( strFileName.length() < 1 ) return;

    mDstPathText->setText( strFileName );
}

void DocSignerDlg::checkUseTSP()
{
    bool bVal = mUseTSPCheck->isChecked();
    mTSPBtn->setEnabled( bVal );
}

void DocSignerDlg::clickTSP()
{
    TimeStampDlg tspDlg;
    tspDlg.exec();
}

void DocSignerDlg::changeCMSData()
{
    QString strType = mCMSDataTypeCombo->currentText();
    QString strData = mCMSDataText->toPlainText();
    QString strLen = getDataLenString( strType, strData );
    mCMSDataLenText->setText( strLen );
}

void DocSignerDlg::changeCMSOutput()
{
    QString strOutput = mCMSOutputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mCMSOutputLenText->setText( strLen );
}

void DocSignerDlg::clickCMSClear()
{
    mCMSDataText->clear();
}

void DocSignerDlg::clickCMSOutputUp()
{
    QString strOutput = mCMSOutputText->toPlainText();
    mCMSDataTypeCombo->setCurrentText( "Hex" );
    mCMSDataText->setPlainText( strOutput );

    mCMSOutputText->clear();
}

void DocSignerDlg::clickCMSView()
{
    int ret = 0;
    BIN binSrc = {0,0};
    CMSInfoDlg cmsInfo = CMSInfoDlg(nullptr, true);

    if( cms_.nLen > 0 )
        JS_BIN_copy( &binSrc, &cms_ );
    else
    {
        QString strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source cms" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }

    ret = JS_CMS_getType( &binSrc );
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

void DocSignerDlg::clickCMSDataView()
{
    int ret = 0;
    BIN binSrc = {0,0};
    CMSInfoDlg cmsInfo = CMSInfoDlg(nullptr, true);

    QString strSrcPath = mSrcPathText->text();

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = JS_CMS_getType( &binSrc );
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

void DocSignerDlg::clickCMSOutputClear()
{
    mCMSOutputText->clear();
}

void DocSignerDlg::clickCMSOutputDecode()
{
    BIN binOut = {0,0};

    QString strOutput = mCMSOutputText->toPlainText();
    getBINFromString( &binOut, DATA_HEX, strOutput );

    berApplet->decodeData( &binOut );
    JS_BIN_reset( &binOut );
}

void DocSignerDlg::initUI()
{
    mCMSEncodeRadio->setChecked(true);
    mCMSAutoDetectCheck->setChecked(true);
    mCMSCmdCombo->addItems( kCMSEncodeList );


    mHashCombo->addItems( kSHAHashList );
    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mTabSigner->setCurrentIndex(0);

    mCMSCipherCombo->addItems( kCipherList );
    mCMSDataTypeCombo->addItems( kDataTypeList );
    mCMSDataTypeCombo->setCurrentText( kDataHex );

    mXMLDataText->setPlaceholderText( tr("data for encryption" ));

    checkCMSEncode();
    checkSrcFile();
    checkDstFile();
    checkUseTSP();
    checkXML_UseTemplate();
    changeCMSCmd();
}

void DocSignerDlg::initialize()
{
    QStringList usedList = getUsedURL();

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
}

void DocSignerDlg::changeCMSCmd()
{
    QString strCmd = mCMSCmdCombo->currentText();

    if( strCmd == kCMSCmdEnvelopedData )
        mCMSCipherCombo->setEnabled( true );
    else
        mCMSCipherCombo->setEnabled( false );

    if( strCmd == kCMSCmdSignedData )
    {
        mUseTSPCheck->setEnabled( true );
        mTSPBtn->setEnabled( true );
    }
    else
    {
        mUseTSPCheck->setEnabled( false );
        mTSPBtn->setEnabled( false );
    }
}

void DocSignerDlg::clickCMSRun()
{
    QString strCmd = mCMSCmdCombo->currentText();

    if( mCMSEncodeRadio->isChecked() == true )
    {
        if( strCmd == kCMSCmdData )
        {
            clickCMSMakeData();
        }
        else if( strCmd == kCMSCmdDigest )
        {
            clickCMSMakeDigest();
        }
        else if( strCmd == kCMSCmdSignedData )
        {
            clickCMSMakeSign();
        }
        else if( strCmd == kCMSCmdEnvelopedData )
        {
            clickCMSEnvelopedData();
        }
        else if( strCmd == kCMSCmdAddSigned )
        {
            clickCMSAddSign();
        }
    }
    else
    {
        if( mCMSAutoDetectCheck->isChecked() == true )
        {
            int type = -1;
            BIN binSrc = {0,0};

            QString strSrcPath = mSrcPathText->text();
            if( mSrcFileCheck->isChecked() == true )
            {
                if( strSrcPath.length() < 1 )
                {
                    berApplet->warningBox( tr( "find a source CMS" ), this );
                    mSrcPathText->setFocus();
                    return;
                }

                JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
            }
            else
            {
                QString strData = mCMSDataText->toPlainText();
                QString strType = mCMSDataTypeCombo->currentText();

                if( strData.length() < 1 )
                {
                    berApplet->warningBox( tr( "Enter a CMS" ), this );
                    mCMSDataText->setFocus();
                    return;
                }

                getBINFromString( &binSrc, strType, strData );
            }

            type = JS_CMS_getType( &binSrc );
            JS_BIN_reset( &binSrc );

            if( type == JS_PKCS7_TYPE_DATA )
                clickCMSGetData();
            else if( type == JS_PKCS7_TYPE_DIGEST )
                clickCMSGetDigest();
            else if( type == JS_PKCS7_TYPE_SIGNED )
                clickCMSVerifySign();
            else if( type == JS_PKCS7_TYPE_ENVELOED )
                clickCMSDevelopedData();
            else
            {
                berApplet->warningBox( tr( "not supported CMS type[%1]").arg( type ), this );
                return;
            }
        }
        else
        {
            if( strCmd == kCMSCmdGetData )
            {
                clickCMSGetData();
            }
            else if( strCmd == kCMSCmdGetDigest )
            {
                clickCMSGetDigest();
            }
            else if( strCmd == kCMSCmdVerifyData )
            {
                clickCMSVerifySign();
            }
            else if( strCmd == kCMSCmdDevelopedData )
            {
                clickCMSDevelopedData();
            }
        }
    }
}

void DocSignerDlg::setDstFile()
{
    QString strExt = "der";
    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();

    if( strSrcPath.length() < 1 )
    {
        QDateTime dateTime;
        dateTime.setSecsSinceEpoch( time(NULL) );
        QString strDateTime = dateTime.toString( "yyyyMMddHHmmss" );

        strSrcPath = berApplet->curPath();
        strSrcPath += "/";
        strSrcPath += QString( "signer_%1.bin" ).arg( strDateTime );
    }

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );

        if( mTabSigner->currentIndex() == 1 )
            strExt = "json";
        else if( mTabSigner->currentIndex() == 2 )
            strExt = "xml";
        else
            strExt = "der";

        strDstPath = QString( "%1/%2_dst.%3" )
                         .arg( fileInfo.path() )
                         .arg( fileInfo.baseName() )
                         .arg( strExt );

        mDstPathText->setText( strDstPath );
    }
}

int DocSignerDlg::getPubKey( BIN *pPubKey )
{
    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        CertManDlg certMan;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        certMan.setMode( ManModeSelCert );
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

    certMan.setMode( ManModeSelCert );
    certMan.setTitle( tr( "Select a sign certificate" ));

    if( certMan.exec() != QDialog::Accepted )
        return -1;

    certMan.getCert( pCert );
    JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

int DocSignerDlg::getPriKey( BIN *pPriKey, BIN *pCert )
{
    if( mUseCertManCheck->isChecked() == true )
    {
        CertManDlg certMan;

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return -1;

        certMan.getPriKey( pPriKey );
        if( pCert ) certMan.getCert( pCert );
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


    QString strHash;
    QString strPolicy;
    const char *pPolicy = NULL;
    QString strURL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    QString strAuth;
    int nStatus = -1;
    BIN binTST = {0,0};

    TimeStampDlg tspDlg;

    if( tspDlg.exec() != QDialog::Accepted )
        return -1;

    strURL = tspDlg.mURLCombo->currentText();
    strPolicy = tspDlg.mPolicyText->text();
    strHash = tspDlg.mHashCombo->currentText();

    if( tspDlg.mAuthGroup->isChecked() == true )
    {
        QString strUser = tspDlg.mUserNameText->text();
        QString strPass = tspDlg.mPasswdText->text();
        QString strUP;
        BIN bin = {0,0};
        char *pBase64 = NULL;


        strUP = QString( "%1:%2" ).arg( strUser ).arg( strPass );
        JS_BIN_set( &bin, (unsigned char *)strUP.toStdString().c_str(), strUP.length() );
        JS_BIN_encodeBase64( &bin, &pBase64 );
        strAuth = QString( "Basic %1").arg( pBase64 );

        JS_BIN_reset( &bin );
        if( pBase64 ) JS_free( pBase64 );
    }

    if( tspDlg.mUseNonceCheck->isChecked() == true )
        nUseNonce = 1;

    if( strPolicy.length() > 0 ) pPolicy = strPolicy.toStdString().c_str();

    ret = JS_TSP_encodeRequest( pSrc, strHash.toStdString().c_str(), pPolicy, nUseNonce, &binReq );
    if( ret != 0 ) goto end;

    if( tspDlg.mAuthGroup->isChecked() == true )
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

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = getPriKeyCert( &binPri, &binCert );
    if( ret != 0 ) goto end;

    if( mUseTSPCheck->isChecked() == true )
    {
        ret = getTSP( &binSrc, &binTSP );
        if( ret != 0 ) goto end;
    }

#if 0
    ret = JS_PKCS7_makeSignedDataWithTSP( strHash.toStdString().c_str(),
                                         &binSrc,
                                         &binPri,
                                         &binCert,
                                         &binTSP,
                                         &binSigned );
#else
    ret = JS_CMS_makeSignedDataWithTSP( strHash.toStdString().c_str(),
                                         &binSrc,
                                         &binPri,
                                         &binCert,
                                         &binTSP,
                                         &binSigned );
#endif

    if( ret == JSR_OK )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binSigned );

        mCMSCmdNameText->setText( kCMSCmdSignedData );
        mCMSOutputText->setPlainText( getHexString( &binSigned ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binSigned, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The CMS file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr( "Signed data creation success" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to make singed data: %1").arg( JERR( ret ) ), this );
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
    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source CMS" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a CMS" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = getCert( &binCert );
    if( ret != 0 ) goto end;

    ret = JS_CMS_getType( &binSrc );
    if( ret != JS_PKCS7_TYPE_SIGNED )
    {
        berApplet->warningBox( tr("This is not a signed data message:%1").arg(ret), this );
        goto end;
    }

#if 0
    ret = JS_PKCS7_verifySignedData( &binSrc, &binCert, &binData );
#else
    ret = JS_CMS_verifySignedData( &binSrc, &binCert, &binData );
#endif

    if( binData.nLen > 0 )
    {
        mCMSCmdNameText->setText( kCMSCmdVerifyData );
        mCMSOutputText->setPlainText( getHexString( &binData ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binData, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The data file[%1] has been saved." ).arg( strDstPath ), this );
        }
    }

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr( "Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to verify: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binData );
}

void DocSignerDlg::clickCMSEnvelopedData()
{
    int ret = 0;
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binData = {0,0};

    QString strSrcPath = mSrcPathText->text();
    QString strCipher = mCMSCipherCombo->currentText();

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "Find a source file" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = getCert( &binCert );
    if( ret != 0 ) goto end;

    ret = JS_CMS_makeEnvelopedData( strCipher.toStdString().c_str(), &binSrc, &binCert, &binData );
    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "Enveloped Data OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to envelop data: %1").arg( JERR( ret ) ), this );
    }

    if( binData.nLen > 0 )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binData );

        mCMSCmdNameText->setText( kCMSCmdEnvelopedData );
        mCMSOutputText->setPlainText( getHexString( &binData ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binData, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The data file[%1] has been saved." ).arg( strDstPath ), this );
        }
    }

end:
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binData );
}

void DocSignerDlg::clickCMSDevelopedData()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSrc = {0,0};
    BIN binData = {0,0};

    QString strSrcPath = mSrcPathText->text();
    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source CMS" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a CMS" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = getPriKeyCert( &binPri, &binCert );
    if( ret != 0 ) goto end;

    ret = JS_CMS_getType( &binSrc );
    if( ret != JS_PKCS7_TYPE_ENVELOED )
    {
        berApplet->warningBox( tr("This is not a enveloped data message:%1").arg(ret), this );
        goto end;
    }

#if 0
    ret = JS_PKCS7_makeDevelopedData( &binSrc, &binPri, &binCert, &binData );
#else
    ret = JS_CMS_makeDevelopedData( &binSrc, &binPri, &binCert, &binData );
#endif

    if( binData.nLen > 0 )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binData );

        mCMSCmdNameText->setText( kCMSCmdDevelopedData );
        mCMSOutputText->setPlainText( getHexString( &binData ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binData, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The data file[%1] has been saved." ).arg( strDstPath ), this );
        }
    }

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "Developed data OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to develop data: %1").arg( JERR( ret ) ), this );
    }



end:
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binData );
}

void DocSignerDlg::clickCMSMakeData()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binCMS = {0,0};


    QString strSrcPath = mSrcPathText->text();

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }


    ret = JS_CMS_makeData( &binSrc, &binCMS );

    if( ret == JSR_OK )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binCMS );

        mCMSCmdNameText->setText( kCMSCmdData );
        mCMSOutputText->setPlainText( getHexString( &binCMS ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binCMS, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The CMS file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr( "CMS data creation success" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to make data: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binCMS );
}

void DocSignerDlg::clickCMSMakeDigest()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binCMS = {0,0};

    QString strHash = mHashCombo->currentText();
    QString strSrcPath = mSrcPathText->text();

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }


    ret = JS_CMS_makeDigest( &binSrc, strHash.toStdString().c_str(), &binCMS );

    if( ret == JSR_OK )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binCMS );

        mCMSCmdNameText->setText( kCMSCmdDigest );
        mCMSOutputText->setPlainText( getHexString( &binCMS ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binCMS, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The CMS file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr( "CMS digest creation success" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to make data: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binCMS );
}

void DocSignerDlg::clickCMSAddSign()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binSigned = {0,0};

    QString strHash = mHashCombo->currentText();

    QString strSrcPath = mSrcPathText->text();

    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = getPriKeyCert( &binPri, &binCert );
    if( ret != 0 ) goto end;

    ret = JS_CMS_addSigner( &binSrc, strHash.toStdString().c_str(), &binPri, &binCert, &binSigned );

    if( ret == JSR_OK )
    {
        JS_BIN_reset( &cms_ );
        JS_BIN_copy( &cms_, &binSigned );

        mCMSCmdNameText->setText( kCMSCmdAddSigned );
        mCMSOutputText->setPlainText( getHexString( &binSigned ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binSigned, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The CMS file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr( "Signed data creation success" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to make singed data: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSigned );
}

void DocSignerDlg::clickCMSGetData()
{
    int ret = 0;

    BIN binSrc = {0,0};
    JCMSInfo sCMSInfo;

    memset( &sCMSInfo, 0x00, sizeof(sCMSInfo));

    QString strSrcPath = mSrcPathText->text();
    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source CMS" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a CMS" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = JS_CMS_getType( &binSrc );
    if( ret != JS_PKCS7_TYPE_DATA )
    {
        berApplet->warningBox( tr("This is not a data message:%1").arg(ret), this );
        goto end;
    }

    ret = JS_CMS_getData( &binSrc, &sCMSInfo );

    if( sCMSInfo.binContent.nLen > 0 )
    {
        mCMSCmdNameText->setText( kCMSCmdGetData );
        mCMSOutputText->setPlainText( getHexString( &sCMSInfo.binContent ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &sCMSInfo.binContent, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The data file[%1] has been saved." ).arg( strDstPath ), this );
        }
    }

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr( "Get OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to get data: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_CMS_resetCMSInfo( &sCMSInfo );
}

void DocSignerDlg::clickCMSGetDigest()
{
    int ret = 0;

    BIN binSrc = {0,0};
    JCMSInfo sCMSInfo;

    memset( &sCMSInfo, 0x00, sizeof(sCMSInfo));

    QString strSrcPath = mSrcPathText->text();
    if( mSrcFileCheck->isChecked() == true )
    {
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source CMS" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileReadBER( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strData = mCMSDataText->toPlainText();
        QString strType = mCMSDataTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a CMS" ), this );
            mCMSDataText->setFocus();
            return;
        }

        getBINFromString( &binSrc, strType, strData );
    }

    ret = JS_CMS_getType( &binSrc );
    if( ret != JS_PKCS7_TYPE_DIGEST )
    {
        berApplet->warningBox( tr("This is not a digest message:%1").arg(ret), this );
        goto end;
    }

    ret = JS_CMS_getDigest( &binSrc, &sCMSInfo );

    if( sCMSInfo.binContent.nLen > 0 )
    {
        mCMSCmdNameText->setText( kCMSCmdGetDigest );
        mCMSOutputText->setPlainText( getHexString( &sCMSInfo.binContent ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &sCMSInfo.binContent, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The data file[%1] has been saved." ).arg( strDstPath ), this );
        }
    }

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "Get digest OK [Verify: %1]" ).arg( sCMSInfo.nVerify ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to get digest: %1").arg( JERR( ret ) ), this );
    }

end:
    JS_BIN_reset( &binSrc );
    JS_CMS_resetCMSInfo( &sCMSInfo );
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
    QString strPayload;

    if( mSrcFileCheck->isChecked() == true )
    {
        BIN binSrc = {0,0};
        QString strSrcPath = mSrcPathText->text();
        char *pString = NULL;

        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source json" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
        JS_BIN_string( &binSrc, &pString );

        if( pString )
        {
            strPayload = pString;
            JS_free( pString );
        }
    }
    else
    {
        strPayload = mJSONPayloadText->toPlainText();

        if( strPayload.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a payload" ), this );
            mJSONPayloadText->setFocus();
            return;
        }
    }

    QJsonDocument jDoc = QJsonDocument::fromJson( strPayload.toLocal8Bit() );
    if( jDoc.isObject() == false )
    {
        berApplet->warningBox( tr( "Payload is not object" ), this );
        mJSONPayloadText->setFocus();
        return;
    }

    ret = getKeyPair( &binPub, &binPri );

//    objJson.setPayload( strPayload );
    objJson.setPayload( jDoc.object() );

    nKeyType = JS_PKI_getPriKeyType( &binPri );
    strAlg = ACMEObject::getAlg( nKeyType, strHash );
    objJWK = ACMEObject::getJWK( &binPub, strHash, strName );
    objProtected = ACMEObject::getJWKProtected( strAlg, objJWK, "", "" );
    objJson.setProtected( objProtected );
    objJson.setSignature( &binPri, strHash );

    mJSON_JWSText->setPlainText( objJson.getPacketJson() );

    if( mDstFileCheck->isChecked() == true )
    {
        BIN binDst = {0,0};
        QString strJWS = mJSON_JWSText->toPlainText();

        JS_BIN_set( &binDst, (unsigned char *)strJWS.toStdString().c_str(), strJWS.length() );
        setDstFile();

        QString strDstPath = mDstPathText->text();
        JS_BIN_fileWrite( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
        berApplet->messageBox( tr( "The json file[%1] has been saved." ).arg( strDstPath ), this );
        JS_BIN_reset( &binDst );
    }

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void DocSignerDlg::clickJSON_VerifySignature()
{
    int ret = 0;
    BIN binPub = {0,0};
    QString strJWS;

    if( mSrcFileCheck->isChecked() == true )
    {
        BIN binSrc = {0,0};
        QString strSrcPath = mSrcPathText->text();
        char *pString = NULL;

        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source json" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
        JS_BIN_string( &binSrc, &pString );

        if( pString )
        {
            strJWS = pString;
            JS_free( pString );
        }
    }
    else
    {
        strJWS = mJSONPayloadText->toPlainText();
        if( strJWS.length() < 1 )
        {
            berApplet->warningBox( tr("There is no JWS payload" ), this );
            mJSONPayloadText->setFocus();
            return;
        }
    }

    ret = getPubKey( &binPub );

    ACMEObject acmeObj;
    acmeObj.setObjectFromJson( strJWS );

    ret = acmeObj.verifySignature( &binPub );

    mJSON_JWSText->setPlainText( acmeObj.getPayloadJSON() );

    if( ret == JSR_VERIFY )
        berApplet->messageBox( tr("Verify OK" ), this );
    else
        berApplet->warningBox( tr("Verify fail: %1").arg( JERR( ret ) ), this );

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

void DocSignerDlg::clickJSON_JWSUp()
{
    QString strJWS = mJSON_JWSText->toPlainText();
    mJSONPayloadText->setPlainText( strJWS );
    mJSON_JWSText->clear();
}

void DocSignerDlg::clickJSON_PayloadView()
{
    QString strPayload = mJSONPayloadText->toPlainText();
    if( strPayload.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no payload" ), this );
        mJSONPayloadText->setFocus();
        return;
    }

    JSONTreeDlg jsonTree(nullptr);
    jsonTree.setJson( strPayload );
    jsonTree.exec();
}

void DocSignerDlg::clickJSON_JWSView()
{
    QString strJWS = mJSON_JWSText->toPlainText();
    if( strJWS.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no JWS" ), this );
        mJSON_JWSText->setFocus();
        return;
    }

    JSONTreeDlg jsonTree(nullptr);
    jsonTree.setJson( strJWS );
    jsonTree.exec();
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

void DocSignerDlg::checkXML_UseTemplate()
{
    bool bVal = mXMLTemplateCheck->isChecked();

    mXMLDataLabel->setEnabled( bVal );
    mXMLDataText->setEnabled( bVal );
    mXMLDataLenText->setEnabled( bVal );
}

void DocSignerDlg::clickXML_BodyClear()
{
    mXMLBodyText->clear();
}

void DocSignerDlg::clickXML_ResClear()
{
    mXMLResText->clear();
}

void DocSignerDlg::clickXML_ResUp()
{
    QString strRes = mXMLResText->toPlainText();
    mXMLBodyText->setPlainText( strRes );
    mXMLResText->clear();
}

void DocSignerDlg::clickXML_MakeSign()
{
    int ret = 0;
    QString strSrcPath;

    BIN binPri = {0,0};
    BIN binSrc = {0,0};
    BIN binDst = {0,0};
    BIN binCert = {0,0};

    if( mSrcFileCheck->isChecked() == true )
    {
        strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source xml" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strBody = mXMLBodyText->toPlainText();
        if( strBody.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a XML body" ), this );
            mXMLBodyText->setFocus();
            return;
        }

        JS_BIN_set( &binSrc, (unsigned char *)strBody.toStdString().c_str(), strBody.length() );
    }


    ret = getPriKey( &binPri, &binCert );

    JS_XML_init();

#if 0
    ret = JS_XML_signWithInfo( strSrcPath.toLocal8Bit().toStdString().c_str(),
                    &binPri,
                    strDstPath.toLocal8Bit().toStdString().c_str() );
#else
    if( mXMLTemplateCheck->isChecked() == true )
        ret = JS_XML_signWithInfoBIN( &binSrc, &binPri, &binDst );
    else
        ret = JS_XML_signDocBIN( &binSrc, &binPri, &binCert, &binDst );
#endif

    if( ret == JSR_OK )
    {
        char *pString = NULL;
        JS_BIN_string( &binDst, &pString );
        mXMLResText->setPlainText( pString );
        if( pString ) JS_free( pString );

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The XML file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr("XML Signature OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to make signature: %1").arg( JERR( ret ) ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binCert );

    return;
}

void DocSignerDlg::clickXML_Encrypt()
{
    int ret = 0;

    BIN binData = {0,0};
    BIN binKey = {0,0};
    BIN binSrc = {0,0};
    BIN binDst = {0,0};

    QString strSrcPath;

    if( mSrcFileCheck->isChecked() == true )
    {
        strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source xml" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strBody = mXMLBodyText->toPlainText();
        if( strBody.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a XML body" ), this );
            mXMLBodyText->setFocus();
            return;
        }

        JS_BIN_set( &binSrc, (unsigned char *)strBody.toStdString().c_str(), strBody.length() );
    }

    if( mXMLTemplateCheck->isChecked() == true )
    {
        QString strData = mXMLDataText->text();
        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a data" ), this );
            mXMLDataText->setFocus();
            return;
        }

        getBINFromString( &binData, DATA_STRING, strData );
    }

    KeyListDlg keyList;
    keyList.setTitle( tr( "Select key" ));
    keyList.setManage(false);

    if( keyList.exec() != QDialog::Accepted )
        return;

    QString strKey = keyList.getKey();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );

    JS_XML_init();

#if 0
    ret = JS_XML_encryptWithInfo(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        &binKey,
        &binBody,
        strDstPath.toLocal8Bit().toStdString().c_str() );
#else
    if( mXMLTemplateCheck->isChecked() == true )
        ret = JS_XML_encryptWithInfoBIN( &binSrc, &binKey, &binData, &binDst );
    else
        ret = JS_XML_encryptBIN( &binSrc, &binKey, &binDst );
#endif

    if( ret == JSR_OK )
    {
        mXMLResText->setPlainText( getHexString( &binDst ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The XML file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr("XML Encrypt OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to encrypt: %1").arg( JERR( ret ) ), this );
    }


end :
    JS_XML_final();

    JS_BIN_reset( &binData );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binSrc );

    return;
}


void DocSignerDlg::clickXML_VerifySign()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binSrc = {0,0};

    QString strSrcPath;

    if( mSrcFileCheck->isChecked() == true )
    {
        strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source xml" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strBody = mXMLBodyText->toPlainText();
        if( strBody.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a XML signature to body" ), this );
            mXMLBodyText->setFocus();
            return;
        }

        JS_BIN_set( &binSrc, (unsigned char *)strBody.toStdString().c_str(), strBody.length() );
    }

    JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );

    ret = getPubKey( &binPub );
    if( ret != 0 ) goto end;

    JS_XML_init();

#if 0
    ret = JS_XML_verify( strSrcPath.toLocal8Bit().toStdString().c_str(), &binPub );
#else
    ret = JS_XML_verifyBIN( &binSrc, &binPub );
#endif

    if( ret == JSR_VERIFY )
    {
        berApplet->messageBox( tr("XML Verify OK" ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to verify: %1").arg( JERR( ret ) ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSrc );

    return;
}

void DocSignerDlg::clickXML_Decrypt()
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binSrc = {0,0};
    BIN binDst = {0,0};

    QString strSrcPath;

    if( mSrcFileCheck->isChecked() == true )
    {
        strSrcPath = mSrcPathText->text();
        if( strSrcPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source xml" ), this );
            mSrcPathText->setFocus();
            return;
        }

        JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );
    }
    else
    {
        QString strBody = mXMLBodyText->toPlainText();
        if( strBody.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a XML body" ), this );
            mXMLBodyText->setFocus();
            return;
        }

        JS_BIN_set( &binSrc, (unsigned char *)strBody.toStdString().c_str(), strBody.length() );
    }

    KeyListDlg keyList;
    keyList.setTitle( tr( "Select key" ));
    keyList.setManage(false);

    if( keyList.exec() != QDialog::Accepted )
        return;

    QString strKey = keyList.getKey();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );

    JS_XML_init();

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

    JS_BIN_fileRead( strSrcPath.toLocal8Bit().toStdString().c_str(), &binSrc );

#if 0
    ret = JS_XML_decrypt(
        strSrcPath.toLocal8Bit().toStdString().c_str(),
        &binKey,
        strDstPath.toLocal8Bit().toStdString().c_str() );
#else
    ret = JS_XML_decryptBIN( &binSrc, &binKey, &binDst );
#endif

    if( ret == JSR_OK )
    {
        mXMLResText->setPlainText( getHexString( &binDst ));

        if( mDstFileCheck->isChecked() == true )
        {
            setDstFile();
            QString strDstPath = mDstPathText->text();
            JS_BIN_fileWrite( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
            berApplet->messageBox( tr( "The XML file[%1] has been saved." ).arg( strDstPath ), this );
        }

        berApplet->messageBox( tr("XML Decrypt OK [%1]" ).arg( strDstPath ), this );
    }
    else
    {
        berApplet->warningBox( tr( "fail to decrypt: %1").arg( JERR( ret ) ), this );
    }

end :
    JS_XML_final();
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binDst );
}

void DocSignerDlg::changeXML_Body()
{
    QString strBody = mXMLBodyText->toPlainText();
    mXMLBodyLenText->setText( QString("%1").arg( strBody.length() ));
}

void DocSignerDlg::changeXML_Data()
{
    int nLen = mXMLDataText->text().length();
    mXMLDataLenText->setText( QString("%1").arg( nLen ));
}
