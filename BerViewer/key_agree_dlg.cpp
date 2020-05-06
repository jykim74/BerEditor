#include <QFileDialog>
#include <QDialogButtonBox>

#include "key_agree_dlg.h"
#include "js_pki.h"

const QStringList sMechList = { "DH", "ECDH" };
const QStringList sGList = { "0", "2", "5" };


KeyAgreeDlg::KeyAgreeDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mGenParamBtn, SIGNAL(clicked()), this, SLOT(genDHParam()));
    connect( mGenDHKeyBtn, SIGNAL(clicked()), this, SLOT(genDHKey()));
    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey() ));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert() ));

    connect( mCalcBtn, SIGNAL(clicked()), this, SLOT(calcualte()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    initialize();

}

KeyAgreeDlg::~KeyAgreeDlg()
{

}

void KeyAgreeDlg::calcualte()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binCert = {0,0};
    BIN binSecret = {0,0};

    if( mMechCombo->currentIndex() == 0 )
    {
        BIN binP = {0,0};
        BIN binG = {0,0};

        JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
        JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );
        JS_BIN_decodeHex( mPrivateKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mPublicKeyText->text().toStdString().c_str(), &binPub );

        ret = JS_PKI_getDHSecret( &binP, &binG, &binPri, &binPub, &binSecret );

        JS_BIN_reset( &binP );
        JS_BIN_reset( &binG );
    }
    else
    {
        JS_BIN_fileRead( mPriKeyPathText->text().toLocal8Bit().toStdString().c_str(), &binPri );
        JS_BIN_fileRead( mCertPathText->text().toLocal8Bit().toStdString().c_str(), &binCert );

        ret = JS_PKI_getECDHSecret( &binPri, &binCert, &binSecret );
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binSecret, &pHex );
        mSecretKeyText->setPlainText(pHex);
        JS_free( pHex );
    }

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSecret );
}

void KeyAgreeDlg::initialize()
{
    mMechCombo->addItems( sMechList );
    mGCombo->addItems( sGList );

    mLengthText->setText( "128" );

    mechChanged(0);
}

void KeyAgreeDlg::genDHParam()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};

    int nLen = mLengthText->text().toInt();
    int nG = mGCombo->currentText().toInt();

    ret = JS_PKI_genDHParam( nLen, nG, &binP, &binG );
    if( ret == 0 )
    {
        char *pHex = NULL;

        JS_BIN_encodeHex( &binG, &pHex );
        if( pHex )
        {
            mGText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

        JS_BIN_encodeHex( &binP, &pHex );
        if( pHex )
        {
            mPText->setPlainText(pHex);
            JS_free( pHex );
            pHex = NULL;
        }
    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
}

void KeyAgreeDlg::genDHKey()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );

    ret = JS_PKI_genDHKey( &binP, &binG, &binPri, &binPub );

    if( ret == 0 )
    {
        char *pHex = NULL;

        JS_BIN_encodeHex( &binPri, &pHex );

        if( pHex )
        {
            mPrivateKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

        JS_BIN_encodeHex( &binPub, &pHex );
        if( pHex )
        {
            mPublicKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void KeyAgreeDlg::findPriKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("ECC PrivateKey file"),
                                                     QDir::currentPath(),
                                                     tr("Key DER File (*.der);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mPriKeyPathText->setText(fileName);
}

void KeyAgreeDlg::findCert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("ECC Certificate file"),
                                                     QDir::currentPath(),
                                                     tr("ECC Cert File (*.crt);;DER File (*.der);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mCertPathText->setText(fileName);
}

void KeyAgreeDlg::mechChanged(int index)
{
    bool bVal;

    if( index == 0 )
        bVal = true;
    else {
        bVal = false;
    }

    mDHGroup->setEnabled(bVal);
    mECDHGroup->setEnabled(!bVal);
}

