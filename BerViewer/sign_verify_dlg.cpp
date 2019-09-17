#include <QFileDialog>

#include "sign_verify_dlg.h"
#include "ber_define.h"
#include "ber_applet.h"
#include "js_bin.h"
#include "js_pki.h"

static const char *dataTypes[] = {
    "String",
    "Hex",
    "Base64"
};

static const char *algTypes[] = {
    "RSA",
    "ECDSA"
};

static const char *hashTypes[] = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512"
};

static const char *versionTypes[] = {
    "V15",
    "V21"
};

static const char *methodTypes[] = {
    "Signature",
    "Verify"
};

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mPubKeyBtn, SIGNAL(clicked()), this, SLOT(findPublicKey()));
}

SignVerifyDlg::~SignVerifyDlg()
{

}

void SignVerifyDlg::initialize()
{
    /*
    QStringList dataList;

    for( int i=0; i < (sizeof(dataTypes) / sizeof(dataTypes[0])); i++ )
        dataList.push_back( dataTypes[i] );
    */

    QStringList algList;
    for( int i=0; i < (sizeof(algTypes) / sizeof(algTypes[0])); i++ )
        algList.push_back( algTypes[i]);
    mAlgTypeCombo->addItems(algList);

    QStringList hashList;
    for( int i=0; i < (sizeof(hashTypes) / sizeof(hashTypes[0])); i++ )
        hashList.push_back(hashTypes[i]);
    mHashTypeCombo->addItems(hashList);

    QStringList versionList;
    for( int i=0; i < (sizeof(versionTypes) / sizeof(versionTypes[0])); i++)
        versionList.push_back(versionTypes[i]);
    mVersionCombo->addItems(versionList);

    QStringList methodList;
    for( int i=0; i < (sizeof(methodTypes) / sizeof(methodTypes[0])); i++ )
        methodList.push_back(methodTypes[i] );
    mMethodCombo->addItems(methodList);
}

void SignVerifyDlg::findPrivateKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;DER Files (*.der)"),
                                                     &selectedFilter,
                                                     options );

    mPriKeyPath->setText(fileName);
}

void SignVerifyDlg::findPublicKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("File name"),
                                                     "/",
                                                     tr("All Files (*);;DER Files (*.der)"),
                                                     &selectedFilter,
                                                     options );

    mPubKeyPath->setText( fileName );
}

void SignVerifyDlg::accept()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;

    QString strInput = mInputText->toPlainText();

    if( mInputStringBtn->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexBtn->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    else if( mInputBase64Btn->isChecked() )
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );

    if( mVersionCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    QString strHash = mHashTypeCombo->currentText();

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        JS_BIN_fileRead( mPriKeyPath->text().toStdString().c_str(), &binPri );

        if( mAlgTypeCombo->currentIndex() == 0 )
            JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), nVersion, &binSrc, &binPri, &binOut );
        else {
            JS_PKI_ECCMakeSign( strHash.toStdString().c_str(), &binSrc, &binPri, &binOut );
        }

        JS_BIN_encodeHex( &binOut, &pOut );
        mOutputText->setPlainText(pOut);
    }
    else
    {
        JS_BIN_fileRead( mPubKeyPath->text().toStdString().c_str(), &binPub );
        JS_BIN_decodeHex( mOutputText->toPlainText().toStdString().c_str(), &binOut );

        if( mAlgTypeCombo->currentIndex() == 0 )
            ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binPub );
        else {
            ret = JS_PKI_ECCVerifySign( strHash.toStdString().c_str(), &binSrc, &binOut, &binPub );
        }

        if( ret == 0 )
            berApplet->messageBox( "Verify Success" );
        else {
            berApplet->warningBox( "Verify Fail" );
        }
    }

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binOut );
    if( pOut ) JS_free( pOut );
}
