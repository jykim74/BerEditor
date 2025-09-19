#include <QStringList>
#include "gen_key_pair_dlg.h"
#include "common.h"
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "js_pqc.h"

#include "ber_applet.h"

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList kECCOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1"
};

static QStringList kEdDSAOptionList = { "Ed25519", "Ed448" };
static QStringList kDSAOptionList = { "1024", "2048", "3072", "4096" };

static QStringList kML_KEMList = {
    JS_PQC_PARAM_ML_KEM_512_NAME,
    JS_PQC_PARAM_ML_KEM_768_NAME,
    JS_PQC_PARAM_ML_KEM_1024_NAME
};

static QStringList kML_DSAList = {
    JS_PQC_PARAM_ML_DSA_44_NAME,
    JS_PQC_PARAM_ML_DSA_65_NAME,
    JS_PQC_PARAM_ML_DSA_87_NAME
};

static QStringList kSLH_DSAList = {
    JS_PQC_PARAM_SLH_DSA_SHA2_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256F_NAME
};


GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mRSARadio, SIGNAL(clicked()), this, SLOT(clickRSA()));
    connect( mECDSARadio, SIGNAL(clicked()), this, SLOT(clickECDSA()));
    connect( mDSARadio, SIGNAL(clicked()), this, SLOT(clickDSA()));
    connect( mEdDSARadio, SIGNAL(clicked()), this, SLOT(clickEdDSA()));
    connect( mSM2Radio, SIGNAL(clicked()), this, SLOT(clickSM2()));
    connect( mML_KEMRadio, SIGNAL(clicked()), this, SLOT(clickML_KEM()));
    connect( mML_DSARadio, SIGNAL(clicked()), this, SLOT(clickML_DSA()));
    connect( mSLH_DSARadio, SIGNAL(clicked()), this, SLOT(clickSLH_DSA()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    initialize();
    mRSARadio->click();
    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GenKeyPairDlg::~GenKeyPairDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
}

void GenKeyPairDlg::initialize()
{
    QIntValidator* intVal = new QIntValidator(1, 65537);
    mExponentText->setValidator( intVal );
    mExponentText->setText( "65537" );
}

void GenKeyPairDlg::setRegInfo( const QString strRegInfo )
{
    QStringList infoList = strRegInfo.split( "&" );
    QString strAlg;
    QString strOption;

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList nameVal = strPart.split("=");

        if( nameVal.size() < 2 ) continue;

        QString strName = nameVal.at(0);
        QString strVal = nameVal.at(1);

        if( strName.toUpper() == "ALG" )
            strAlg = strVal;

        if( strName.toUpper() == "PARAM" )
            strOption = strVal;
    }

    if( strAlg.toUpper() == "RSA" )
        mRSARadio->click();
    else if( strAlg.toUpper() == "ECDSA" || strAlg.toUpper() == "EC" )
        mECDSARadio->click();
    else if( strAlg.toUpper() == "DSA" )
        mDSARadio->click();
    else if( strAlg.toUpper() == "EDDSA" )
        mEdDSARadio->click();
    else if( strAlg.toUpper() == "SM2" )
        mSM2Radio->click();
    else if( strAlg.toUpper() == "ML_KEM" )
        mML_KEMRadio->click();
    else if( strAlg.toUpper() == "ML_DSA" )
        mML_DSARadio->click();
    else if( strAlg.toUpper() == "SLH_DSA" )
        mSLH_DSARadio->click();

    if( strOption.length() > 0 ) mOptionCombo->setCurrentText( strOption );
}

void GenKeyPairDlg::setFixName( const QString strName )
{
    mNameText->setText( strName );
    mNameText->setStyleSheet( kReadOnlyStyle );
    mNameText->setReadOnly(true);
}

const QString GenKeyPairDlg::getPriKeyHex()
{
    return getHexString( &pri_key_ );
}

const QString GenKeyPairDlg::getPubKeyHex()
{
    return getHexString( &pub_key_ );
}

void GenKeyPairDlg::clickRSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kRSAOptionList );
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled( true );
    mExponentText->setEnabled( true );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickECDSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kECCOptionList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Named Curve" ));
}

void GenKeyPairDlg::clickDSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kDSAOptionList );
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickEdDSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kEdDSAOptionList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Named Curve" ));
}

void GenKeyPairDlg::clickSM2()
{
    mOptionCombo->clear();
    mOptionCombo->addItem( "SM2" );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Named Curve" ));
}

void GenKeyPairDlg::clickML_KEM()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kML_KEMList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickML_DSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kML_DSAList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickSLH_DSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kSLH_DSAList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickOK()
{
    int ret = 0;

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );

    QString strName = mNameText->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    if( mRSARadio->isChecked() )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        int nExponent = mExponentText->text().toInt();
        if( nExponent <= 0 )
        {
            berApplet->warningBox( tr( "Enter exponent" ), this );
            return;
        }

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &pub_key_, &pri_key_ );
    }
    else if( mECDSARadio->isChecked() )
    {
        QString strCurve = mOptionCombo->currentText();
        ret = JS_PKI_ECCGenKeyPair( strCurve.toStdString().c_str(), &pub_key_, &pri_key_ );
    }
    else if( mSM2Radio->isChecked() )
    {
        QString strCurve = mOptionCombo->currentText();
        ret = JS_PKI_ECCGenKeyPair( strCurve.toStdString().c_str(), &pub_key_, &pri_key_ );
    }
    else if( mDSARadio->isChecked() )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &pub_key_, &pri_key_ );
    }
    else if( mEdDSARadio->isChecked() )
    {
        int nParam = -1;
        QString strCurve = mOptionCombo->currentText();

        if( strCurve == "Ed25519" )
            nParam = JS_EDDSA_PARAM_25519;
        else
            nParam = JS_EDDSA_PARAM_448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &pub_key_, &pri_key_ );
    }
    else if( mML_KEMRadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_ML_KEM_genKeyPair( nParam, &pub_key_, &pri_key_ );
    }
    else if( mML_DSARadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_ML_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
    }
    else if( mSLH_DSARadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_SLH_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
    }

    if( ret == JSR_OK )
        return QDialog::accept();
    else
    {
        berApplet->warnLog( tr( "fail to generate keypair: %1").arg( ret ), this);
        return QDialog::reject();
    }
}
