#include <QElapsedTimer>
#include <QRegExpValidator>

#include "make_pri_key_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "export_dlg.h"

#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"

MakePriKeyDlg::MakePriKeyDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mPublicKeyCheck, SIGNAL(clicked()), this, SLOT(checkPublicKey()));
    connect( mExportBtn, SIGNAL(clicked()), this, SLOT(clickExport()));
    connect( mMakeBtn, SIGNAL(clicked()), this, SLOT(clickMake()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeAlg(int)));

    connect( mRSA_NText, SIGNAL(textChanged()), this, SLOT(changeRSA_N()));
    connect( mRSA_EText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_E(const QString&)));
    connect( mRSA_DText, SIGNAL(textChanged()), this, SLOT(changeRSA_D()));
    connect( mRSA_PText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_P(const QString&)));
    connect( mRSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_Q(const QString&)));
    connect( mRSA_DMP1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMP1(const QString&)));
    connect( mRSA_DMQ1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMQ1(const QString&)));
    connect( mRSA_IQMPText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_IQMP(const QString&)));

    connect( mECC_PubXText, SIGNAL(textChanged()), this, SLOT(changeECC_PubX()));
    connect( mECC_PubYText, SIGNAL(textChanged()), this, SLOT(changeECC_PubY()));
    connect( mECC_PrivateText, SIGNAL(textChanged()), this, SLOT(changeECC_Private()));
    connect( mECC_CurveSNCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeECC_CurveSN()));

    connect( mDSA_GText, SIGNAL(textChanged()), this, SLOT(changeDSA_G()));
    connect( mDSA_PText, SIGNAL(textChanged()), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q(const QString&)));
    connect( mDSA_PublicText, SIGNAL(textChanged()), this, SLOT(changeDSA_Public()));
    connect( mDSA_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Private(const QString&)));

    connect( mRawPublicText, SIGNAL(textChanged()), this, SLOT(changeRawPublic()));
    connect( mRawPrivateText, SIGNAL(textChanged()), this, SLOT(changeRawPrivate()));
    connect( mRawNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeRawName()));

    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));
    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mCheckPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickCheckPubKey()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    tabRSA->layout()->setSpacing(5);
    tabRSA->layout()->setMargin(5);
    tabECC->layout()->setSpacing(5);
    tabECC->layout()->setMargin(5);
    tabDSA->layout()->setSpacing(5);
    tabDSA->layout()->setMargin(5);
    tabRaw->layout()->setSpacing(5);
    tabRaw->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

MakePriKeyDlg::~MakePriKeyDlg()
{

}

void MakePriKeyDlg::initUI()
{
    mRSA_DText->setPlaceholderText( tr("Hex value" ));
    mRSA_NText->setPlaceholderText( tr( "Hex value" ));
    mRSA_EText->setPlaceholderText( tr( "Hex value" ));
    mRSA_PText->setPlaceholderText( tr( "Hex value" ));
    mRSA_QText->setPlaceholderText( tr( "Hex value" ));
    mRSA_DMP1Text->setPlaceholderText( tr( "Hex value" ));
    mRSA_DMQ1Text->setPlaceholderText( tr( "Hex value" ));
    mRSA_IQMPText->setPlaceholderText( tr( "Hex value" ));

    mECC_PrivateText->setPlaceholderText( tr("Hex value" ));
    mECC_PubXText->setPlaceholderText( tr("Hex value" ));
    mECC_PubYText->setPlaceholderText( tr( "Hex value" ));

    mDSA_GText->setPlaceholderText( tr("Hex value"));
    mDSA_PText->setPlaceholderText( tr("Hex value"));
    mDSA_QText->setPlaceholderText( tr("Hex value"));
    mDSA_PublicText->setPlaceholderText( tr("Hex value"));
    mDSA_PrivateText->setPlaceholderText( tr("Hex value"));

    mRawPrivateText->setPlaceholderText( tr("Hex value" ));
    mRawPublicText->setPlaceholderText( tr("Hex value"));

    mAlgCombo->addItems( kAsymAlgList );
    mParamCombo->addItems( kRSAOptionList );
    mParamCombo->setCurrentText( "2048" );

    QRegExp regExp("^[0-9-]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
    mExponentText->setValidator( regVal );
    mExponentText->setText( "65537" );
    mExponentText->setPlaceholderText( tr("Decimal value"));

    mTabWidget->setCurrentIndex( RSA_IDX );
    mECC_CurveSNCombo->addItems( kECDSAOptionList );
    changeECC_CurveSN();

    mRawNameCombo->addItems( kRawAlgList );
    changeRawName();
}

void MakePriKeyDlg::initialize()
{

}

void MakePriKeyDlg::changeRSA_N()
{
    QString strN = mRSA_NText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strN );
    mRSA_NLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_E( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_ELenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_D()
{
    QString strD = mRSA_DText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strD );
    mRSA_DLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_P( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_PLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_QLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_DMP1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMP1LenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_DMQ1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMQ1LenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRSA_IQMP( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_IQMPLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeECC_PubX()
{
    QString strPubX = mECC_PubXText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubX );
    mECC_PubXLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeECC_PubY()
{
    QString strPubY = mECC_PubYText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubY );
    mECC_PubYLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeECC_Private()
{
    QString strPrivate = mECC_PrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPrivate );
    mECC_PrivateLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeECC_CurveSN()
{
    char sOID[1024];
    QString strSN = mECC_CurveSNCombo->currentText();

    memset( sOID, 0x00, sizeof(sOID));

    JS_PKI_getOIDFromSN( strSN.toStdString().c_str(), sOID );
    mECC_CurveOIDText->setText( sOID );
}

void MakePriKeyDlg::changeDSA_G()
{
    QString strG = mDSA_GText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strG );
    mDSA_GLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeDSA_P()
{
    QString strP = mDSA_PText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strP );
    mDSA_PLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeDSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_QLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeDSA_Public()
{
    QString strPublic = mDSA_PublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPublic );
    mDSA_PublicLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeDSA_Private( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_PrivateLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRawPublic()
{
    QString strRawPublic = mRawPublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPublic );
    mRawPublicLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRawPrivate()
{
    QString strRawPrivte = mRawPrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPrivte );
    mRawPrivateLenText->setText( QString("%1").arg(strLen));
}

void MakePriKeyDlg::changeRawName()
{
    QString strAlg = mRawNameCombo->currentText();

    mRawParamCombo->clear();

    if( strAlg == kAlgEdDSA )
    {
        mRawParamCombo->addItems( kEdDSAOptionList );
    }
    else if( strAlg == kAlgMLDSA )
    {
        mRawParamCombo->addItems( kML_DSAOptionList );
    }
    else if( strAlg == kAlgMLKEM )
    {
        mRawParamCombo->addItems( kML_KEMOptionList );
    }
    else if( strAlg == kAlgSLHDSA )
    {
        mRawParamCombo->addItems( kSLH_DSAOptionList );
    }
}

void MakePriKeyDlg::clickExport()
{
    int ret = 0;
    int nIndex = mTabWidget->currentIndex();
    BIN binPri = {0,0};
    ExportDlg exportDlg;
    bool bPri = true;
    QString strName = "PrivateKey";

    if( mPublicKeyCheck->isChecked() == true )
    {
        bPri = false;
        strName = "PublicKey";
    }

    if( nIndex == RSA_IDX )
    {
        ret = getRSA( &binPri, bPri );
    }
    else if( nIndex == ECC_IDX )
    {
        ret = getECC( &binPri, bPri );
    }
    else if( nIndex == DSA_IDX )
    {
        ret = getDSA( &binPri, bPri );
    }
    else
    {
        ret = getRaw( &binPri, bPri );
    }

    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr("Export failed: %1").arg( JERR(ret)), this );
        goto end;
    }

    exportDlg.setName( strName );
    exportDlg.setPrivateKey( &binPri );
    exportDlg.exec();

end :
    JS_BIN_reset( &binPri );
}

void MakePriKeyDlg::clickMake()
{
    int ret = 0;
    qint64 us = 0;
    QElapsedTimer timer;

    BIN binPub = {0,0};
    BIN binPri = {0,0};

    QString strAlg = mAlgCombo->currentText();
    QString strParam = mParamCombo->currentText();
    QString strExponent = mExponentText->text();

    if( strAlg == kAlgRSA )
    {
        JRSAKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        mTabWidget->setCurrentIndex( RSA_IDX );

        int nKeySize = strParam.toInt();
        int nExponent = strExponent.toInt();

        timer.start();
        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        if( mRSA_DText->isEnabled() ) mRSA_DText->setPlainText( sKeyVal.pD );
        if( mRSA_NText->isEnabled() ) mRSA_NText->setPlainText( sKeyVal.pN );
        if( mRSA_EText->isEnabled() ) mRSA_EText->setText( sKeyVal.pE );
        if( mRSA_PText->isEnabled() ) mRSA_PText->setText( sKeyVal.pP );
        if( mRSA_QText->isEnabled() ) mRSA_QText->setText( sKeyVal.pQ );
        if( mRSA_DMP1Text->isEnabled() ) mRSA_DMP1Text->setText( sKeyVal.pDMP1 );
        if( mRSA_DMQ1Text->isEnabled() ) mRSA_DMQ1Text->setText( sKeyVal.pDMQ1 );
        if( mRSA_IQMPText->isEnabled() ) mRSA_IQMPText->setText( sKeyVal.pIQMP );

        JS_PKI_resetRSAKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgECDSA || strAlg == kAlgSM2 )
    {
        JECKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        mTabWidget->setCurrentIndex( ECC_IDX );

        timer.start();
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        mECC_CurveSNCombo->setCurrentText( strParam );
        if( mECC_CurveOIDText->isEnabled() ) mECC_CurveOIDText->setText( sKeyVal.pCurveOID );
        if( mECC_PrivateText->isEnabled() ) mECC_PrivateText->setPlainText( sKeyVal.pPrivate );
        if( mECC_PubXText->isEnabled() ) mECC_PubXText->setPlainText( sKeyVal.pPubX );
        if( mECC_PubYText->isEnabled() ) mECC_PubYText->setPlainText( sKeyVal.pPubY );

        JS_PKI_resetECKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgDSA )
    {
        JDSAKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        mTabWidget->setCurrentIndex( DSA_IDX );

        int nKeySize = strParam.toInt();

        timer.start();
        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getDSAKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        if( mDSA_GText->isEnabled() ) mDSA_GText->setPlainText( sKeyVal.pG );
        if( mDSA_PText->isEnabled() ) mDSA_PText->setPlainText( sKeyVal.pP );
        if( mDSA_QText->isEnabled() ) mDSA_QText->setText( sKeyVal.pQ );
        if( mDSA_PublicText->isEnabled() ) mDSA_PublicText->setPlainText( sKeyVal.pPublic );
        if( mDSA_PrivateText->isEnabled() ) mDSA_PrivateText->setText( sKeyVal.pPrivate );

        JS_PKI_resetDSAKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgEdDSA )
    {
        int nParam = -1;
        JRawKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        mTabWidget->setCurrentIndex( RAW_IDX );

        if( strParam == "Ed25519" )
            nParam = JS_EDDSA_PARAM_25519;
        else
            nParam = JS_EDDSA_PARAM_448;

        timer.start();
        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getRawKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;


        if( mRawNameCombo->isEnabled() ) mRawNameCombo->setCurrentText( strAlg );
        if( mRawParamCombo->isEnabled() ) mRawParamCombo->setCurrentText( strParam );
        if( mRawPrivateText->isEnabled() ) mRawPrivateText->setPlainText( sKeyVal.pPri );
        if( mRawPublicText->isEnabled() ) mRawPublicText->setPlainText( sKeyVal.pPub );

        JS_PKI_resetRawKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgMLDSA )
    {
        JRawKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        mTabWidget->setCurrentIndex( RAW_IDX );

        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        timer.start();
        ret = JS_ML_DSA_genKeyPair( nParam, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getRawKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        if( mRawNameCombo->isEnabled() ) mRawNameCombo->setCurrentText( strAlg );
        if( mRawParamCombo->isEnabled() ) mRawParamCombo->setCurrentText( strParam );
        if( mRawPrivateText->isEnabled() ) mRawPrivateText->setPlainText( sKeyVal.pPri );
        if( mRawPublicText->isEnabled() ) mRawPublicText->setPlainText( sKeyVal.pPub );

        JS_PKI_resetRawKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgMLKEM )
    {
        JRawKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));
        mTabWidget->setCurrentIndex( RAW_IDX );

        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        timer.start();
        ret = JS_ML_KEM_genKeyPair( nParam, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getRawKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        if( mRawNameCombo->isEnabled() ) mRawNameCombo->setCurrentText( strAlg );
        if( mRawParamCombo->isEnabled() ) mRawParamCombo->setCurrentText( strParam );
        if( mRawPrivateText->isEnabled() ) mRawPrivateText->setPlainText( sKeyVal.pPri );
        if( mRawPublicText->isEnabled() ) mRawPublicText->setPlainText( sKeyVal.pPub );

        JS_PKI_resetRawKeyVal( &sKeyVal );
    }
    else if( strAlg == kAlgSLHDSA )
    {
        JRawKeyVal sKeyVal;
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));
        mTabWidget->setCurrentIndex( RAW_IDX );

        int nParam = JS_PQC_param( strParam.toStdString().c_str() );

        timer.start();
        ret = JS_SLH_DSA_genKeyPair( nParam, &binPub, &binPri );
        us = timer.nsecsElapsed() / 1000;

        if( ret != CKR_OK ) goto end;

        ret = JS_PKI_getRawKeyVal( &binPri, &sKeyVal );
        if( ret != CKR_OK ) goto end;

        if( mRawNameCombo->isEnabled() ) mRawNameCombo->setCurrentText( strAlg );
        if( mRawParamCombo->isEnabled() ) mRawParamCombo->setCurrentText( strParam );
        if( mRawPrivateText->isEnabled() ) mRawPrivateText->setPlainText( sKeyVal.pPri );
        if( mRawPublicText->isEnabled() ) mRawPublicText->setPlainText( sKeyVal.pPub );

        JS_PKI_resetRawKeyVal( &sKeyVal );
    }

end :
    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to generate key pair: %1").arg( JERR(ret) ), this );
    }
    else
    {
        berApplet->log( QString( "%1(%2) Key generation time : %3 ms")
                           .arg( strAlg )
                           .arg( mParamCombo->currentText() )
                           .arg( getMS( us )));

        berApplet->messageBox( tr( "%1 private key generated" ).arg( strAlg ), this );
    }

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
}

void MakePriKeyDlg::clearRSA()
{
    mRSA_DText->clear();
    mRSA_EText->clear();
    mRSA_NText->clear();
    mRSA_DMP1Text->clear();
    mRSA_DMQ1Text->clear();
    mRSA_IQMPText->clear();
    mRSA_PText->clear();
    mRSA_QText->clear();
}

void MakePriKeyDlg::clearECC()
{
    mECC_CurveOIDText->clear();
    mECC_PrivateText->clear();
    mECC_PubXText->clear();
    mECC_PubYText->clear();
}

void MakePriKeyDlg::clearDSA()
{
    mDSA_GText->clear();
    mDSA_PText->clear();
    mDSA_QText->clear();
    mDSA_PrivateText->clear();
    mDSA_PublicText->clear();
}

void MakePriKeyDlg::clearRaw()
{
    mRawPrivateText->clear();
    mRawPublicText->clear();
}

void MakePriKeyDlg::clickClearAll()
{
    clearRSA();
    clearECC();
    clearDSA();
    clearRaw();
}

int MakePriKeyDlg::getRSA( BIN *pRSA, bool bPri )
{
    int ret = 0;
    JRSAKeyVal sKeyVal;

    BIN binN = {0,0};
    BIN binE = {0,0};
    BIN binD = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binDMP1 = {0,0};
    BIN binDMQ1 = {0,0};
    BIN binIQMP = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    ret = getBINFromString( &binN, DATA_HEX, mRSA_NText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binE, DATA_HEX, mRSA_EText->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binD, DATA_HEX, mRSA_DText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binP, DATA_HEX, mRSA_PText->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binQ, DATA_HEX, mRSA_QText->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binDMP1, DATA_HEX, mRSA_DMP1Text->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binDMQ1, DATA_HEX, mRSA_DMQ1Text->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binIQMP, DATA_HEX, mRSA_IQMPText->text() );
    FORMAT_WARN_RET(ret);

    ret = JS_PKI_setRSAKeyVal( &sKeyVal,
                        binN.nLen > 0 ? getHexString( &binN ).toStdString().c_str() : NULL,
                        binE.nLen > 0 ? getHexString( &binE ).toStdString().c_str() : NULL,
                        binD.nLen > 0 ? getHexString( &binD ).toStdString().c_str() : NULL,
                        binP.nLen > 0 ? getHexString( &binP ).toStdString().c_str() : NULL,
                        binQ.nLen > 0 ? getHexString( &binQ ).toStdString().c_str() : NULL,
                        binDMP1.nLen > 0 ? getHexString( &binDMP1 ).toStdString().c_str() : NULL,
                        binDMQ1.nLen > 0 ? getHexString( &binDMQ1 ).toStdString().c_str() : NULL,
                        binIQMP.nLen > 0 ? getHexString( &binIQMP ).toStdString().c_str() : NULL );

    if( ret != CKR_OK ) goto end;

    if( bPri == true )
        ret = JS_PKI_encodeRSAPrivateKey( &sKeyVal, pRSA );
    else
        ret = JS_PKI_encodeRSAPublicKey( &sKeyVal, pRSA );

end :
    JS_PKI_resetRSAKeyVal( &sKeyVal );
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binD );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binDMP1 );
    JS_BIN_reset( &binDMQ1 );
    JS_BIN_reset( &binIQMP );

    return ret;
}

int MakePriKeyDlg::getECC( BIN *pECC, bool bPri )
{
    int ret = 0;
    JECKeyVal sKeyVal;

    QString strOID = mECC_CurveOIDText->text();

    BIN binPri = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    ret = getBINFromString( &binPri, DATA_HEX, mECC_PrivateText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binPubX, DATA_HEX, mECC_PubXText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binPubY, DATA_HEX, mECC_PubYText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = JS_PKI_setECKeyVal( &sKeyVal,
                             strOID.toStdString().c_str(),
                             binPubX.nLen > 0 ? getHexString( &binPubX ).toStdString().c_str() : NULL,
                             binPubY.nLen > 0 ? getHexString( &binPubY ).toStdString().c_str() : NULL,
                             binPri.nLen > 0 ? getHexString( &binPri ).toStdString().c_str() : NULL );

    if( ret != CKR_OK ) goto end;

    if( bPri == true )
        ret = JS_PKI_encodeECPrivateKey( &sKeyVal, pECC );
    else
        ret = JS_PKI_encodeECPublicKey( &sKeyVal, pECC );

end :
    JS_PKI_resetECKeyVal( &sKeyVal );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    return ret;
}

int MakePriKeyDlg::getDSA( BIN *pDSA, bool bPri )
{
    int ret = 0;
    JDSAKeyVal sKeyVal;

    BIN binG = {0,0};
    BIN binP = {0,0};
    BIN binQ = {0,0};
    BIN binPub = {0,0};
    BIN binPri = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    ret = getBINFromString( &binG, DATA_HEX, mDSA_GText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binP, DATA_HEX, mDSA_PText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binQ, DATA_HEX, mDSA_QText->text() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binPub, DATA_HEX, mDSA_PublicText->toPlainText() );
    FORMAT_WARN_RET(ret);

    ret = getBINFromString( &binPri, DATA_HEX, mDSA_PrivateText->text() );
    FORMAT_WARN_RET(ret);

    ret = JS_PKI_setDSAKeyVal( &sKeyVal,
                                binG.nLen > 0 ? getHexString( &binG ).toStdString().c_str() : NULL,
                                binP.nLen > 0 ? getHexString( &binP ).toStdString().c_str() : NULL,
                                binQ.nLen > 0 ? getHexString( &binQ ).toStdString().c_str() : NULL,
                                binPub.nLen > 0 ? getHexString( &binPub ).toStdString().c_str() : NULL,
                                binPri.nLen > 0 ? getHexString( &binPri ).toStdString().c_str() : NULL );

    if( ret != CKR_OK ) goto end;

    if( bPri == true )
        ret = JS_PKI_encodeDSAPrivateKey( &sKeyVal, pDSA );
    else
        ret = JS_PKI_encodeDSAPublicKey( &sKeyVal, pDSA );

end :
    JS_PKI_resetDSAKeyVal( &sKeyVal );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );

    return ret;
}

int MakePriKeyDlg::getRaw( BIN *pRaw, bool bPri )
{
    int ret = 0;
    JRawKeyVal sKeyVal;
    QString strAlg = mRawNameCombo->currentText();
    QString strParam = mRawParamCombo->currentText();

    BIN binPub = {0,0};
    BIN binPri = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    ret = JS_PKI_setRawKeyVal( &sKeyVal,
                              strAlg.toStdString().c_str(),
                              strParam.toStdString().c_str(),
                              binPub.nLen > 0 ? getHexString( &binPub ).toStdString().c_str() : NULL,
                              binPri.nLen > 0 ? getHexString( &binPri ).toStdString().c_str() : NULL );

    if( ret != CKR_OK ) goto end;

    if( bPri == true )
        ret = JS_PKI_encodeRawPrivateKey( &sKeyVal, pRaw );
    else
        ret = JS_PKI_encodeRawPublicKey( &sKeyVal, pRaw );

end :
    JS_PKI_resetRawKeyVal( &sKeyVal );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );

    return ret;
}

void MakePriKeyDlg::changeTab( int index )
{
    if( index == RSA_IDX )
    {
        mAlgCombo->setCurrentText( kAlgRSA );
    }
    else if( index == ECC_IDX )
    {
        mAlgCombo->setCurrentText( kAlgECDSA );
    }
    else if( index == DSA_IDX )
    {
        mAlgCombo->setCurrentText( kAlgDSA );
    }
    else if( index == RAW_IDX )
    {
        mAlgCombo->setCurrentText( kAlgEdDSA );
    }
}

void MakePriKeyDlg::changeAlg( int index )
{
    QString strAlg = mAlgCombo->currentText();

    mParamCombo->clear();


    if( strAlg == kAlgRSA )
    {
        mParamCombo->addItems( kRSAOptionList );
        mParamCombo->setCurrentText( "2048" );
        mExponentLabel->setEnabled( true );
        mExponentText->setEnabled( true );
    }
    else if( strAlg == kAlgECDSA )
    {
        mParamCombo->addItems( kECDSAOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgSM2 )
    {
        mParamCombo->addItem( "SM2" );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgDSA )
    {
        mParamCombo->addItems( kDSAOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgEdDSA )
    {
        mParamCombo->addItems( kEdDSAOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgMLDSA )
    {
        mParamCombo->addItems( kML_DSAOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgMLKEM )
    {
        mParamCombo->addItems( kML_KEMOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
    else if( strAlg == kAlgSLHDSA )
    {
        mParamCombo->addItems( kSLH_DSAOptionList );
        mExponentLabel->setEnabled( false );
        mExponentText->setEnabled( false );
    }
}

void MakePriKeyDlg::checkPublicKey()
{
    bool bVal = mPublicKeyCheck->isChecked();

    if( bVal == true )
        mHeadLabel->setText( tr( "Make a private key" ));
    else
        mHeadLabel->setText( tr( "Make a public key" ));

    setEnableRSA_D( !bVal );
    setEnableRSA_P( !bVal );
    setEnableRSA_Q( !bVal );
    setEnableRSA_DMP1( !bVal );
    setEnableRSA_DMQ1( !bVal );
    setEnableRSA_IQMP( !bVal );

    setEnableECC_Private( !bVal );

    setEnableDSA_Private( !bVal );

    setEnableRawPrivate( !bVal );

    mCheckKeyPairBtn->setEnabled( !bVal );
}

void MakePriKeyDlg::clickDecode()
{
    int ret = 0;
    int nIndex = mTabWidget->currentIndex();
    BIN binPri = {0,0};
    bool bPri = true;


    if( mPublicKeyCheck->isChecked() == true )
    {
        bPri = false;
    }

    if( nIndex == RSA_IDX )
    {
        ret = getRSA( &binPri, bPri );
    }
    else if( nIndex == ECC_IDX )
    {
        ret = getECC( &binPri, bPri );
    }
    else if( nIndex == DSA_IDX )
    {
        ret = getDSA( &binPri, bPri );
    }
    else
    {
        ret = getRaw( &binPri, bPri );
    }

    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr("Export failed: %1").arg( JERR(ret)), this );
        goto end;
    }

    berApplet->decodeData( &binPri );

end :
    JS_BIN_reset( &binPri );
}

void MakePriKeyDlg::clickCheckKeyPair()
{
    int ret = 0;
    int nIndex = mTabWidget->currentIndex();
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    bool bPri = true;

    if( mPublicKeyCheck->isChecked() == true )
    {
        return;
    }

    if( nIndex == RSA_IDX )
    {
        ret = getRSA( &binPri, bPri );
    }
    else if( nIndex == ECC_IDX )
    {
        ret = getECC( &binPri, bPri );
    }
    else if( nIndex == DSA_IDX )
    {
        ret = getDSA( &binPri, bPri );
    }
    else
    {
        ret = getRaw( &binPri, bPri );
    }

    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr("Export failed: %1").arg( JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_getPubKeyFromPri( &binPri, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );
    if( ret == 1 )
        ret = JSR_VALID;

    if( ret == JSR_VALID )
        berApplet->messageBox( tr( "KeyPair is matched" ), this );
    else
        berApplet->warningBox( tr( "KeyPais is not matched" ), this );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}

void MakePriKeyDlg::clickCheckPubKey()
{
    int ret = 0;
    int nIndex = mTabWidget->currentIndex();
    BIN binPri = {0,0};
    bool bPri = true;


    if( mPublicKeyCheck->isChecked() == true )
    {
        bPri = false;
    }

    if( nIndex == RSA_IDX )
    {
        ret = getRSA( &binPri, bPri );
    }
    else if( nIndex == ECC_IDX )
    {
        ret = getECC( &binPri, bPri );
    }
    else if( nIndex == DSA_IDX )
    {
        ret = getDSA( &binPri, bPri );
    }
    else
    {
        ret = getRaw( &binPri, bPri );
    }

    if( ret != CKR_OK )
    {
        berApplet->warningBox( tr("Export failed: %1").arg( JERR(ret)), this );
        goto end;
    }

    if( bPri == false )
    {
        ret = JS_PKI_checkPublicKey( &binPri );
    }
    else
    {
        BIN binPub = {0,0};
        JS_PKI_getPubKeyFromPriKey( &binPri, &binPub );
        ret = JS_PKI_checkPublicKey( &binPub );
        JS_BIN_reset( &binPub );
    }

    if( ret == JSR_VALID )
        berApplet->messageBox( tr( "PublicKey is valid" ), this );
    else
        berApplet->warningBox( tr( "PublicKey is invalid" ), this );

end :
    JS_BIN_reset( &binPri );
}

void MakePriKeyDlg::setEnableRSA_N( bool bVal )
{
    mRSA_NLabel->setEnabled( bVal );
    mRSA_NText->setEnabled( bVal );
    mRSA_NLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_E( bool bVal )
{
    mRSA_ELabel->setEnabled( bVal );
    mRSA_EText->setEnabled( bVal );
    mRSA_ELenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_D( bool bVal )
{
    mRSA_DLabel->setEnabled( bVal );
    mRSA_DText->setEnabled( bVal );
    mRSA_DLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_P( bool bVal )
{
    mRSA_PLabel->setEnabled( bVal );
    mRSA_PText->setEnabled( bVal );
    mRSA_PLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_Q( bool bVal )
{
    mRSA_QLabel->setEnabled( bVal );
    mRSA_QText->setEnabled( bVal );
    mRSA_QLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_DMP1( bool bVal )
{
    mRSA_DMP1Label->setEnabled( bVal );
    mRSA_DMP1Text->setEnabled( bVal );
    mRSA_DMP1LenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_DMQ1( bool bVal )
{
    mRSA_DMQ1Label->setEnabled( bVal );
    mRSA_DMQ1Text->setEnabled( bVal );
    mRSA_DMQ1LenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRSA_IQMP( bool bVal )
{
    mRSA_IQMPLabel->setEnabled( bVal );
    mRSA_IQMPText->setEnabled( bVal );
    mRSA_IQMPLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableECC_Private( bool bVal )
{
    mECC_PrivateLabel->setEnabled( bVal );
    mECC_PrivateText->setEnabled( bVal );
    mECC_PrivateLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableECC_PubX( bool bVal )
{
    mECC_PubXLabel->setEnabled( bVal );
    mECC_PubXText->setEnabled( bVal );
    mECC_PubXLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableECC_PubY( bool bVal )
{
    mECC_PubYLabel->setEnabled( bVal );
    mECC_PubYText->setEnabled( bVal );
    mECC_PubYLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableDSA_P( bool bVal )
{
    mDSA_PLabel->setEnabled( bVal );
    mDSA_PText->setEnabled( bVal );
    mDSA_PLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableDSA_Q( bool bVal )
{
    mDSA_QLabel->setEnabled( bVal );
    mDSA_QText->setEnabled( bVal );
    mDSA_QLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableDSA_G( bool bVal )
{
    mDSA_GLabel->setEnabled( bVal );
    mDSA_GText->setEnabled( bVal );
    mDSA_GLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableDSA_Private( bool bVal )
{
    mDSA_PrivateLabel->setEnabled( bVal );
    mDSA_PrivateText->setEnabled( bVal );
    mDSA_PrivateLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableDSA_Public( bool bVal )
{
    mDSA_PublicLabel->setEnabled( bVal );
    mDSA_PublicText->setEnabled( bVal );
    mDSA_PLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRawPublic( bool bVal )
{
    mRawPublicLabel->setEnabled( bVal );
    mRawPublicText->setEnabled( bVal );
    mRawPublicLenText->setEnabled( bVal );
}

void MakePriKeyDlg::setEnableRawPrivate( bool bVal )
{
    mRawPrivateLabel->setEnabled( bVal );
    mRawPrivateText->setEnabled( bVal );
    mRawPrivateLenText->setEnabled( bVal );
}
