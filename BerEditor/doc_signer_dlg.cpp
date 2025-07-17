#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamReader>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>


#include "doc_signer_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "acme_tree_dlg.h"
#include "acme_object.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"

DocSignerDlg::DocSignerDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mFindSrcPathBtn, SIGNAL(clicked()), this, SLOT(findSrcPath()));
    connect( mFindDstPathBtn, SIGNAL(clicked()), this, SLOT(findDstPath()));

    connect( mJSONPayloadText, SIGNAL(textChanged()), this, SLOT(changeJSON_Payload()));
    connect( mJSON_JWSText, SIGNAL(textChanged()), this, SLOT(changeJSON_JWS()));

    connect( mJSONComputeSignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_ComputeSignature()));
    connect( mJSONVerifySignatureBtn, SIGNAL(clicked()), this, SLOT(clickJSON_VerifySignature()));
    connect( mJSONPayloadClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadClear()));
    connect( mJSONPayloadViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_PayloadView()));
    connect( mJSON_JWSClearBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSClear()));
    connect( mJSON_JWSViewBtn, SIGNAL(clicked()), this, SLOT(clickJSON_JWSView()));

    connect( mXMLMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickXML_MakeSign()));
    connect( mXMLEncryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt()));
    connect( mXMLVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickXML_VerifySign()));
    connect( mXMLDecryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Decrypt()));

    connect( mXMLBodyText, SIGNAL(textChanged()), this, SLOT(changeXML_Body()));
    connect( mXMLSignText, SIGNAL(textChanged()), this, SLOT(changeXML_Sign()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mJSONPayloadClearBtn->setFixedWidth(34);
    mJSONPayloadViewBtn->setFixedWidth(34);
    mJSON_JWSClearBtn->setFixedWidth(34);
    mJSON_JWSViewBtn->setFixedWidth(34);

    mTabJSON->layout()->setSpacing(5);
    mTabJSON->layout()->setMargin(5);

    mTabXML->layout()->setSpacing(5);
    mTabXML->layout()->setMargin(5);

//    mTabPDF->layout()->setSpacing(5);
//    mTabPDF->layout()->setMargin(5);

//    mTabDOC->layout()->setSpacing(5);
//    mTabDOC->layout()->setMargin(5);
#endif


    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

DocSignerDlg::~DocSignerDlg()
{

}

void DocSignerDlg::clickClearAll()
{

}

void DocSignerDlg::findSrcPath()
{
    QString strPath = mSrcPathText->text();
    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BIN, strPath );

    if( strFileName.length() < 1 ) return;

    mSrcPathText->setText( strFileName );
}

void DocSignerDlg::findDstPath()
{
    QString strPath = mDstPathText->text();
    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BIN, strPath );

    if( strFileName.length() < 1 ) return;

    mDstPathText->setText( strFileName );
}

void DocSignerDlg::initUI()
{
    mHashCombo->addItems( kHashList );
    mTabSigner->setCurrentIndex(0);
}

void DocSignerDlg::initialize()
{

}

void DocSignerDlg::clickJSON_ComputeSignature()
{
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

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        JCertInfo sCertInfo;
        CertManDlg certMan;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return;

        certMan.getPriKey( &binPri );
        certMan.getCert( &binCert );
        JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
        strName = sCertInfo.pSubjectName;
        JS_PKI_getPubKeyFromCert( &binCert, &binPub );
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
            return;

        strPubPath = keyPairMan.getPubPath();
        strPriPath = keyPairMan.getPriPath();
        strName = keyPairMan.getName();

        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
        JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
    }

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
    BIN binPub = {0,0};
    QString strJWS = mJSON_JWSText->toPlainText();

    if( strJWS.length() < 1 )
    {
        berApplet->warningBox( tr("There is no JWS" ), this );
        return;
    }

    if( mUseCertManCheck->isChecked() == true )
    {
        BIN binCert = {0,0};
        CertManDlg certMan;

        certMan.setMode( ManModeSelBoth );
        certMan.setTitle( tr( "Select a sign certificate" ));

        if( certMan.exec() != QDialog::Accepted )
            return;

        certMan.getCert( &binCert );
        JS_PKI_getPubKeyFromCert( &binCert, &binPub );
        JS_BIN_reset( &binCert );
    }
    else
    {
        KeyPairManDlg keyPairMan;
        keyPairMan.setTitle( tr( "Select keypair" ));
        keyPairMan.setMode( KeyPairModeSelect );

        if( keyPairMan.exec() != QDialog::Accepted )
            return;

        QString strPubPath = keyPairMan.getPubPath();

        JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );
    }


    ACMEObject acmeObj;
    acmeObj.setObjectFromJson( strJWS );

    int ret = acmeObj.verifySignature( &binPub );
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

void DocSignerDlg::clickXML_MakeSign()
{
    QString strBody = mXMLBodyText->toPlainText();

    xml_.addData( strBody );

    QString strSign = xml_.text().toString();
    mXMLSignText->setPlainText( strSign );
}

#if 1
int
sign_file(const char* tmpl_file, const char* key_file) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;

    assert(tmpl_file);
    assert(key_file);

    /* load template */
    doc = xmlReadFile(tmpl_file, NULL, XML_PARSE_PEDANTIC | XML_PARSE_NONET);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", tmpl_file);
        goto done;
    }

    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", tmpl_file);
        goto done;
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecOpenSSLAppKeyLoadEx(key_file, xmlSecKeyDataTypePrivate, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, BAD_CAST key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature failed\n");
        goto done;
    }

    /* print signed document to stdout */
    xmlDocDump(stdout, doc);

    /* success */
    res = 0;

done:
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }

    if(doc != NULL) {
        xmlFreeDoc(doc);
    }
    return(res);
}
#endif

void DocSignerDlg::clickXML_Encrypt()
{

#if 1

#ifndef XMLSEC_NO_XSLT
    xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    xsltSecPrefs = xsltNewSecurityPrefs();
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return;
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return;
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(NULL) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH and/or LTDL_LIBRARY_PATH) environment variables.\n");
        return(-1);
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */


    /* Init crypto library */
    if(xmlSecOpenSSLAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return;
    }

    /* Init xmlsec-crypto library */
    if(xmlSecOpenSSLInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return;
    }

    if(sign_file( "temp_file.xml", "temp_file.key") < 0) {
        return;
    }


    /* Shutdown xmlsec-crypto library */
    xmlSecOpenSSLShutdown();

    /* Shutdown crypto library */
    xmlSecOpenSSLAppShutdown();

    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(xsltSecPrefs);
    xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    return;
#endif

}

void DocSignerDlg::clickXML_VerifySign()
{

}

void DocSignerDlg::clickXML_Decrypt()
{

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
