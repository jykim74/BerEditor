#include <QSettings>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamReader>
#include <QFileInfo>

#include "doc_signer_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "acme_tree_dlg.h"
#include "acme_object.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "key_list_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"
#include "js_pki_xml.h"


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
    connect( mXMLMakeSign2Btn, SIGNAL(clicked()), this, SLOT(clickXML_MakeSign2()));
    connect( mXMLEncryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt()));
    connect( mXMLEncrypt2Btn, SIGNAL(clicked()), this, SLOT(clickXML_Encrypt2()));
    connect( mXMLVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickXML_VerifySign()));
    connect( mXMLDecryptBtn, SIGNAL(clicked()), this, SLOT(clickXML_Decrypt()));

    connect( mXMLBodyText, SIGNAL(textChanged()), this, SLOT(changeXML_Body()));
    connect( mXMLSignText, SIGNAL(textChanged()), this, SLOT(changeXML_Sign()));

    connect( mPDFMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickPDF_MakeSign()));
    connect( mPDFVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickPDF_VerifySign()));
    connect( mDocMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickDoc_MakeSign()));
    connect( mDocVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickDoc_VerifySign()));

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

    mTabPDF->layout()->setSpacing(5);
    mTabPDF->layout()->setMargin(5);

    mTabDOC->layout()->setSpacing(5);
    mTabDOC->layout()->setMargin(5);
#endif


    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

DocSignerDlg::~DocSignerDlg()
{

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

void DocSignerDlg::findSrcPath()
{
    QString strPath = mSrcPathText->text();
    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_XML, strPath );

    if( strFileName.length() < 1 ) return;

    mSrcPathText->setText( strFileName );

    if( mDstPathText->text().length() < 1 )
    {
        QFileInfo fileInfo( strFileName );
        QString strDstPath;

        strDstPath = QString( "%1/%2_dst.%3" )
                         .arg( fileInfo.path() )
                         .arg( fileInfo.baseName() )
                         .arg( fileInfo.suffix() );

        mDstPathText->setText( strDstPath );
    }
}

void DocSignerDlg::findDstPath()
{
    QString strPath = mDstPathText->text();
    QString strFileName = berApplet->findSaveFile( this, JS_FILE_TYPE_XML, strPath );

    if( strFileName.length() < 1 ) return;

    mDstPathText->setText( strFileName );
}

void DocSignerDlg::initUI()
{
    mHashCombo->addItems( kSHAHashList );
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
        berApplet->warningBox( tr( "find a destination xml" ), this );
        mDstPathText->setFocus();
        return;
    }

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    QString strPriPath = keyPairMan.getPriPath();
    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );

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
        berApplet->warningBox( tr( "find a destination xml" ), this );
        mDstPathText->setFocus();
        return;
    }

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    QString strPriPath = keyPairMan.getPriPath();

    JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binPri );
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

    KeyPairManDlg keyPairMan;
    keyPairMan.setTitle( tr( "Select keypair" ));
    keyPairMan.setMode( KeyPairModeSelect );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    QString strPubPath = keyPairMan.getPubPath();
    JS_BIN_fileReadBER( strPubPath.toLocal8Bit().toStdString().c_str(), &binPub );

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
        berApplet->messageBox( tr("XML Decrypt OK" ), this );
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

void DocSignerDlg::clickPDF_MakeSign()
{

}

void DocSignerDlg::clickPDF_VerifySign()
{

}

void DocSignerDlg::clickDoc_MakeSign()
{

}

void DocSignerDlg::clickDoc_VerifySign()
{

}
