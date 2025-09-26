#include <QStringList>
#include <QElapsedTimer>

#include "gen_key_pair_dlg.h"
#include "common.h"
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_tools.h"
#include "js_pqc.h"

#include "ber_applet.h"





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
    mOptionCombo->addItems( kECDSAOptionList );
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
    mOptionCombo->addItems( kML_KEMOptionList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickML_DSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kML_DSAOptionList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickSLH_DSA()
{
    mOptionCombo->clear();
    mOptionCombo->addItems( kSLH_DSAOptionList );
    mExponentLabel->setEnabled( false );
    mExponentText->setEnabled( false );
    mOptionLabel->setText( tr("Key Length" ));
}

void GenKeyPairDlg::clickOK()
{
    int ret = 0;
    QString strKeyType;

    qint64 us = 0;
    QElapsedTimer timer;

    QString strName = mNameText->text();

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );

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
        strKeyType = JS_PKI_KEY_NAME_RSA;

        if( nExponent <= 0 )
        {
            berApplet->warningBox( tr( "Enter exponent" ), this );
            return;
        }

        timer.start();
        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mECDSARadio->isChecked() )
    {
        QString strCurve = mOptionCombo->currentText();

        strKeyType = JS_PKI_KEY_NAME_ECDSA;

        timer.start();
        ret = JS_PKI_ECCGenKeyPair( strCurve.toStdString().c_str(), &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mSM2Radio->isChecked() )
    {
        QString strCurve = mOptionCombo->currentText();

        strKeyType = JS_PKI_KEY_NAME_SM2;

        timer.start();
        ret = JS_PKI_ECCGenKeyPair( strCurve.toStdString().c_str(), &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mDSARadio->isChecked() )
    {
        int nKeySize = mOptionCombo->currentText().toInt();

        strKeyType = JS_PKI_KEY_NAME_DSA;

        timer.start();
        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mEdDSARadio->isChecked() )
    {
        int nParam = -1;
        QString strCurve = mOptionCombo->currentText();
        strKeyType = JS_PKI_KEY_NAME_EDDSA;

        if( strCurve == "Ed25519" )
            nParam = JS_EDDSA_PARAM_25519;
        else
            nParam = JS_EDDSA_PARAM_448;

        timer.start();
        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mML_KEMRadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_ML_KEM;

        timer.start();
        ret = JS_ML_KEM_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mML_DSARadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_ML_DSA;

        timer.start();
        ret = JS_ML_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mSLH_DSARadio->isChecked() )
    {
        QString strParam = mOptionCombo->currentText();
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_SLH_DSA;

        timer.start();
        ret = JS_SLH_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret == JSR_OK )
    {
        berApplet->log( QString( "%1(%2) Key generation time : %3 ms")
                           .arg( strKeyType )
                           .arg( mOptionCombo->currentText() )
                           .arg( getMS( us )));

        return QDialog::accept();
    }
    else
    {
        berApplet->warnLog( tr( "fail to generate keypair: %1").arg( ret ), this);
        return QDialog::reject();
    }
}
