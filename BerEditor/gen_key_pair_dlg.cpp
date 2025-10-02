#include <QStringList>
#include <QElapsedTimer>
#include <QSettings>

#include "gen_key_pair_dlg.h"
#include "common.h"
#include "js_error.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_tools.h"
#include "js_pqc.h"

#include "ber_applet.h"
#include "settings_mgr.h"


const QString sSetGenKeyPairDefault = "GenKeyPairDefault";


GenKeyPairDlg::GenKeyPairDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

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

void GenKeyPairDlg::initUI()
{
    QIntValidator* intVal = new QIntValidator(1, 65537);
    mExponentText->setValidator( intVal );
    mExponentText->setText( "65537" );

    QString strName = "NewKeyPair";
    mNameText->setText( strName );
    mNameText->setSelection(0,strName.length());
}

void GenKeyPairDlg::initialize()
{
    QString strDefault = getDefault();
    if( strDefault.length() > 1 )
    {
        mSetDefaultCheck->setChecked( true );

        QStringList setList = strDefault.split(":");
        if( setList.size() > 0 )
        {
            QString strAlg = setList.at(0);

            if( strAlg == JS_PKI_KEY_NAME_RSA )
                mRSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_ECDSA )
                mECDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_SM2 )
                mSM2Radio->click();
            else if( strAlg == JS_PKI_KEY_NAME_DSA )
                mDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_EDDSA )
                mEdDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_ML_KEM )
                mML_KEMRadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
                mML_DSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
                mSLH_DSARadio->click();
        }

        if( setList.size() > 1 )
        {
            QString strParam = setList.at(1);
            mOptionCombo->setCurrentText( strParam );
        }
    }
    else
    {
        mRSARadio->click();
    }
}

void GenKeyPairDlg::setDefault( const QString strDefault )
{
    QSettings sets;
    sets.beginGroup( kEnvTempGroup );
    sets.setValue( sSetGenKeyPairDefault, strDefault );
    sets.endGroup();
}

const QString GenKeyPairDlg::getDefault()
{
    QString strDefault;

    QSettings sets;
    sets.beginGroup( kEnvTempGroup );
    strDefault = sets.value( sSetGenKeyPairDefault, "" ).toString();
    sets.endGroup();

    return strDefault;
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
    QString strParam = mOptionCombo->currentText();

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
        int nKeySize = strParam.toInt();
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
        strKeyType = JS_PKI_KEY_NAME_ECDSA;

        timer.start();
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mSM2Radio->isChecked() )
    {
        strKeyType = JS_PKI_KEY_NAME_SM2;

        timer.start();
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mDSARadio->isChecked() )
    {
        int nKeySize = strParam.toInt();

        strKeyType = JS_PKI_KEY_NAME_DSA;

        timer.start();
        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mEdDSARadio->isChecked() )
    {
        int nParam = -1;
        strKeyType = JS_PKI_KEY_NAME_EDDSA;

        if( strParam == "Ed25519" )
            nParam = JS_EDDSA_PARAM_25519;
        else
            nParam = JS_EDDSA_PARAM_448;

        timer.start();
        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mML_KEMRadio->isChecked() )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_ML_KEM;

        timer.start();
        ret = JS_ML_KEM_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mML_DSARadio->isChecked() )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_ML_DSA;

        timer.start();
        ret = JS_ML_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mSLH_DSARadio->isChecked() )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        strKeyType = JS_PKI_KEY_NAME_SLH_DSA;

        timer.start();
        ret = JS_SLH_DSA_genKeyPair( nParam, &pub_key_, &pri_key_ );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret == JSR_OK )
    {
        QString strDefault;

        if( mSetDefaultCheck->isChecked() == true )
        {
            strDefault = QString( "%1:%2" ).arg( strKeyType ).arg( strParam );
        }

        setDefault( strDefault );

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
