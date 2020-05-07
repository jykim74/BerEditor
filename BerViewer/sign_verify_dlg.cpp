#include <QFileDialog>

#include "sign_verify_dlg.h"
#include "ber_define.h"
#include "ber_applet.h"
#include "js_bin.h"
#include "js_pki.h"

static QStringList algTypes = {
    "RSA",
    "ECDSA"
};

static QStringList hashTypes = {
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512"
};

static QStringList versionTypes = {
    "V15",
    "V21"
};

static QStringList methodTypes = {
    "Signature",
    "Verify"
};

SignVerifyDlg::SignVerifyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));
    connect( mCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mAlgTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged(int)));
}

SignVerifyDlg::~SignVerifyDlg()
{

}

void SignVerifyDlg::initialize()
{
    mAlgTypeCombo->addItems(algTypes);
    mHashTypeCombo->addItems(hashTypes);
    mVersionCombo->addItems(versionTypes);
    mMethodCombo->addItems(methodTypes);
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

void SignVerifyDlg::findCert()
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

    mCertPath->setText( fileName );
}

void SignVerifyDlg::algChanged(int index)
{
    if( index == 0 )
        mVersionCombo->setEnabled(true);
    else
        mVersionCombo->setEnabled(false);
}

void SignVerifyDlg::accept()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binPri = {0,0};
    BIN binCert = {0,0};
    BIN binOut = {0,0};
    int nVersion = 0;
    char *pOut = NULL;

    QString strInput = mInputText->toPlainText();
    if( strInput.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data"), this );
        return;
    }

    if( mInputStringBtn->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
    else if( mInputHexBtn->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
    }
    else if( mInputBase64Btn->isChecked() )
    {
        strInput.remove(QRegExp("[\t\r\n\\s]"));
        JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
    }

    if( mVersionCombo->currentIndex() == 0 )
        nVersion = JS_PKI_RSA_PADDING_V15;
    else {
        nVersion = JS_PKI_RSA_PADDING_V21;
    }

    QString strHash = mHashTypeCombo->currentText();

    if( mMethodCombo->currentIndex() == SIGN_SIGNATURE )
    {
        if( mPriKeyPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find private key" ), this );
            goto end;
        }

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
        if( mCertPath->text().isEmpty() )
        {
            berApplet->warningBox( tr( "You have to find certificate"), this );
            goto end;
        }

        JS_BIN_fileRead( mCertPath->text().toStdString().c_str(), &binCert );
        JS_BIN_decodeHex( mOutputText->toPlainText().toStdString().c_str(), &binOut );

        if( mAlgTypeCombo->currentIndex() == 0 )
            ret = JS_PKI_RSAVerifySignWithCert( strHash.toStdString().c_str(), nVersion, &binSrc, &binOut, &binCert );
        else {
            ret = JS_PKI_ECCVerifySignWithCert( strHash.toStdString().c_str(), &binSrc, &binOut, &binCert );
        }

        if( ret == 1 )
            berApplet->messageBox( tr("Verify Success") );
        else {
            berApplet->warningBox( tr("Verify Fail") );
        }
    }

end :

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binOut );
    if( pOut ) JS_free( pOut );
}
