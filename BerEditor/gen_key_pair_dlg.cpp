#include <QStringList>
#include "gen_key_pair_dlg.h"
#include "common.h"
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "ber_applet.h"
#include "settings_mgr.h"

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList kECCOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1", "SM2"
};

static QStringList kEdDSAOptionList = { "Ed25519", "Ed448" };
static QStringList kDSAOptionList = { "1024", "2048", "3072", "4096" };


GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mRSACheck, SIGNAL(clicked()), this, SLOT(clickRSA()));
    connect( mECDSACheck, SIGNAL(clicked()), this, SLOT(clickECDSA()));
    connect( mDSACheck, SIGNAL(clicked()), this, SLOT(clickDSA()));
    connect( mEdDSACheck, SIGNAL(clicked()), this, SLOT(clickEdDSA()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    initialize();
    mRSACheck->click();
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

    mHsmCheck->setEnabled(berApplet->settingsMgr()->hsmUse());
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
            mRSACheck->click();
    else if( strAlg.toUpper() == "ECDSA" || strAlg.toUpper() == "EC" )
            mECDSACheck->click();
    else if( strAlg.toUpper() == "DSA" )
            mDSACheck->click();
    else if( strAlg.toUpper() == "EDDSA" )
            mEdDSACheck->click();

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

    if( mRSACheck->isChecked() )
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
    else if( mECDSACheck->isChecked() )
    {
        QString strCurve = mOptionCombo->currentText();
        ret = JS_PKI_ECCGenKeyPair( strCurve.toStdString().c_str(), &pub_key_, &pri_key_ );
    }
    else if( mDSACheck->isChecked() )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &pub_key_, &pri_key_ );
    }
    else if( mEdDSACheck->isChecked() )
    {
        int nParam = -1;
        QString strCurve = mOptionCombo->currentText();

        if( strCurve == "Ed25519" )
            nParam = JS_PKI_KEY_TYPE_ED25519;
        else
            nParam = JS_PKI_KEY_TYPE_ED448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &pub_key_, &pri_key_ );
    }

    if( ret == 0 )
        return QDialog::accept();
    else
    {
        berApplet->warnLog( tr( "fail to generate keypair: %1").arg( ret ), this);
        return QDialog::reject();
    }
}
