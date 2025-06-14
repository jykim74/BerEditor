/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QDialogButtonBox>

#include "key_agree_dlg.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "common.h"
#include "ber_applet.h"
#include "cert_man_dlg.h"
#include "key_pair_man_dlg.h"
#include "export_dlg.h"

const QStringList sGList = { "02", "05" };
const QStringList sParamList = { "512", "1024", "2048", "3072", "4096" };


KeyAgreeDlg::KeyAgreeDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mECDHParamCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeECDHParam(int)));

    connect( mGenParamBtn, SIGNAL(clicked()), this, SLOT(genDHParam()));
    connect( mExportParamBtn, SIGNAL(clicked()), this, SLOT(exportDHParam()));
    connect( mImportParamBtn, SIGNAL(clicked()), this, SLOT(importDHParam()));
    connect( mADHPriBtn, SIGNAL(clicked()), this, SLOT(genADHPri()));
    connect( mBDHPriBtn, SIGNAL(clicked()), this, SLOT(genBDHPri()));
    connect( mAGenDHKeyBtn, SIGNAL(clicked()), this, SLOT(genADHKey()));
    connect( mBGenDHKeyBtn, SIGNAL(clicked()), this, SLOT(genBDHKey()));
    connect( mAGenPriKeyBtn, SIGNAL(clicked()), this, SLOT(genAECDHPriKey()));
    connect( mAGenPubKeyBtn, SIGNAL(clicked()), this, SLOT(genAECDHPubKey()));
    connect( mAFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findAECDHPriKey() ));
    connect( mAGetFromCertManBtn, SIGNAL(clicked()), this, SLOT(getAFromCertMan()));
    connect( mAGetFromKeyPairMan, SIGNAL(clicked()), this, SLOT(getAFromKeyPair()));
    connect( mBGenPriKeyBtn, SIGNAL(clicked()), this, SLOT(genBECDHPriKey()));
    connect( mBGenPubKeyBtn, SIGNAL(clicked()), this, SLOT(genBECDHPubKey()));
    connect( mBFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findBECDHPriKey()));
    connect( mBGetFromCertManBtn, SIGNAL(clicked()), this, SLOT(getBFromCertMan()));
    connect( mBGetFromKeyPairBtn, SIGNAL(clicked()), this, SLOT(getBFromKeyPair()));
    connect( mAGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(genAKeyPair()));
    connect( mBGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(genBKeyPair()));
    connect( mACheckPubKeyBtn, SIGNAL(clicked()), this, SLOT(checkAPubKey()));
    connect( mBCheckPubKeyBtn, SIGNAL(clicked()), this, SLOT(checkBPubKey()));
    connect( mACheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(checkAKeyPair()));
    connect( mBCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(checkBKeyPair()));

    connect( mSecretClearBtn, SIGNAL(clicked()), this, SLOT(secretClear()));
    connect( mACalcBtn, SIGNAL(clicked()), this, SLOT(calcualteA()));
    connect( mBCalcBtn, SIGNAL(clicked()), this, SLOT(calcualteB()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mPText, SIGNAL(textChanged()), this, SLOT(pChanged()));
    connect( mSecretKeyText, SIGNAL(textChanged()), this, SLOT(secretKeyChanged()));
    connect( mAPrivateKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(APriKeyChanged()));
    connect( mAPublicKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(APubKeyChanged()));
    connect( mBPrivateKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(BPriKeyChanged()));
    connect( mBPublicKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(BPubKeyChanged()));
    connect( mAECDHPriKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(AECDHPriKeyChanged()));
    connect( mAECDHPubKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(AECDHPubKeyChanged()));
    connect( mBECDHPriKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(BECDHPriKeyChanged()));
    connect( mBECDHPubKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(BECDHPubKeyChanged()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDHTab->layout()->setSpacing(5);
    mDHTab->layout()->setMargin(5);
    mECDHTab->layout()->setSpacing(5);
    mECDHTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    mACalcBtn->setDefault(true);
}

KeyAgreeDlg::~KeyAgreeDlg()
{

}

void KeyAgreeDlg::calcualteA()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binSecX = {0,0};
    BIN binSecY = {0,0};

    if( mTabWidget->currentIndex() == 0 )
    {
        BIN binP = {0,0};
        BIN binG = {0,0};

        if( mPText->toPlainText().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter P value" ), this );
            mPText->setFocus();
            return;
        }

        if( mAPrivateKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter A Private Key" ), this );
            mAPrivateKeyText->setFocus();
            return;
        }

        if( mBPublicKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter B Public Key" ), this );
            mBPublicKeyText->setFocus();
            return;
        }

        JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
        JS_BIN_decodeHex( mGCombo->currentText().toStdString().c_str(), &binG );
        JS_BIN_decodeHex( mAPrivateKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mBPublicKeyText->text().toStdString().c_str(), &binPub );


        ret = JS_PKI_getDHSecret( &binP, &binG, &binPri, &binPub, &binSecX );

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- DH Calculate A" );
            berApplet->logLine2();
            berApplet->log( QString ( "P          : %1" ).arg( getHexString(&binP)));
            berApplet->log( QString ( "G          : %1" ).arg( getHexString(&binG)));
            berApplet->log( QString ( "PrivateKey : %1" ).arg( getHexString(&binPri)));
            berApplet->log( QString ( "PublicKey  : %1" ).arg( getHexString(&binPub)));
            berApplet->log( QString ( "Secret     : %1" ).arg( getHexString(&binSecX)));
            berApplet->logLine();
        }
        else
        {
            berApplet->warnLog( tr( "fail to calculate Secret: %1").arg( ret ), this );
        }

        JS_BIN_reset( &binP );
        JS_BIN_reset( &binG );
    }
    else
    {
        BIN binX = {0,0};
        BIN binY = {0,0};

        if( mAECDHPriKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter ECDH A Private Key"), this );
            mAECDHPriKeyText->setFocus();
            return;
        }

        if( mBECDHPubKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter ECDH B Public Key" ), this );
            mBECDHPubKeyText->setFocus();
            return;
        }

        JS_BIN_decodeHex( mAECDHPriKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mBECDHPubKeyText->text().toStdString().c_str(), &binPub );

        JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
        JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);

        ret = JS_PKI_getECDHComputeKey( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binX, &binY, &binSecX, &binSecY );

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- ECDH Calculate A" );
            berApplet->logLine2();
            berApplet->log( QString( "PrivateKey : %1").arg( getHexString( &binPri )));
            berApplet->log( QString( "X          : %1").arg( getHexString( &binX )));
            berApplet->log( QString( "Y          : %1").arg( getHexString( &binY )));
            berApplet->log( QString( "SecretX    : %1").arg( getHexString( &binSecX )));
            berApplet->log( QString( "SecretY    : %1").arg( getHexString( &binSecY )));
            berApplet->logLine();
        }
        else
        {
            berApplet->warnLog( tr( "fail to calculate Secret: %1").arg( ret ), this );
        }

        JS_BIN_reset( &binX );
        JS_BIN_reset( &binY );
    }

    if( ret == 0 )
    {
        mSecretKeyText->setPlainText(getHexString(binSecX.pVal, binSecX.nLen));
        if( binSecY.nLen > 0 ) mSecretKeyText->appendPlainText(getHexString(binSecY.pVal, binSecY.nLen));
    }

    update();
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSecX );
    JS_BIN_reset( &binSecY );
}

void KeyAgreeDlg::calcualteB()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binSecX = {0,0};
    BIN binSecY = {0,0};

    if( mTabWidget->currentIndex() == 0 )
    {
        BIN binP = {0,0};
        BIN binG = {0,0};


        JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
        JS_BIN_decodeHex( mGCombo->currentText().toStdString().c_str(), &binG );
        JS_BIN_decodeHex( mBPrivateKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mAPublicKeyText->text().toStdString().c_str(), &binPub );

        if( mPText->toPlainText().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter P value" ), this );
            mPText->setFocus();
            return;
        }

        if( mBPrivateKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter B Private Key" ), this );
            mBPrivateKeyText->setFocus();
            return;
        }

        if( mAPublicKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter A Public Key" ), this );
            mAPublicKeyText->setFocus();
            return;
        }


        ret = JS_PKI_getDHSecret( &binP, &binG, &binPri, &binPub, &binSecX );

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- DH Calculate B" );
            berApplet->logLine2();
            berApplet->log( QString ( "P          : %1" ).arg( getHexString(&binP)));
            berApplet->log( QString ( "G          : %1" ).arg( getHexString(&binG)));
            berApplet->log( QString ( "PrivateKey : %1" ).arg( getHexString(&binPri)));
            berApplet->log( QString ( "PublicKey  : %1" ).arg( getHexString(&binPub)));
            berApplet->log( QString ( "Secret     : %1" ).arg( getHexString(&binSecX)));
            berApplet->logLine();
        }
        else
        {
            berApplet->warnLog( tr( "fail to calculate Secret: %1").arg( ret ), this );
        }

        JS_BIN_reset( &binP );
        JS_BIN_reset( &binG );
    }
    else
    {
        BIN binX = {0,0};
        BIN binY = {0,0};

        if( mBECDHPriKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter ECDH B Private Key"), this );
            mBECDHPriKeyText->setFocus();
            return;
        }

        if( mAECDHPubKeyText->text().length() < 1 )
        {
            berApplet->warningBox( tr( "Enter ECDH A Public Key" ), this );
            mAECDHPubKeyText->setFocus();
            return;
        }

        JS_BIN_decodeHex( mBECDHPriKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mAECDHPubKeyText->text().toStdString().c_str(), &binPub );

        JS_BIN_set( &binX, binPub.pVal, binPub.nLen/2 );
        JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen/2 );

        ret = JS_PKI_getECDHComputeKey( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binX, &binY, &binSecX, &binSecY );

        if( ret == 0 )
        {
            berApplet->logLine();
            berApplet->log( "-- ECDH Calculate A" );
            berApplet->logLine2();
            berApplet->log( QString( "PrivateKey : %1").arg( getHexString( &binPri )));
            berApplet->log( QString( "X          : %1").arg( getHexString( &binX )));
            berApplet->log( QString( "Y          : %1").arg( getHexString( &binY )));
            berApplet->log( QString( "SecretX    : %1").arg( getHexString( &binSecX )));
            berApplet->log( QString( "SecretY    : %1").arg( getHexString( &binSecY )));
            berApplet->logLine();
        }
        else
        {
            berApplet->warnLog( tr( "fail to calculate Secret: %1").arg( ret ), this );
        }

        JS_BIN_reset( &binX );
        JS_BIN_reset( &binY );
    }

    if( ret == 0 )
    {
        mSecretKeyText->setPlainText(getHexString( binSecX.pVal, binSecX.nLen ));
        if( binSecY.nLen > 0 ) mSecretKeyText->appendPlainText(getHexString(binSecY.pVal, binSecY.nLen));
    }

    update();
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSecX );
    JS_BIN_reset( &binSecY );
}

void KeyAgreeDlg::secretClear()
{
    mSecretKeyText->clear();
    update();
}

void KeyAgreeDlg::initialize()
{
    mGCombo->addItems( sGList );
    mECDHParamCombo->addItems( kECCParamList );
    mECDHParamCombo->setCurrentText( "prime256v1" );

    mPText->setPlaceholderText( tr( "Hex value" ) );
    mAPrivateKeyText->setPlaceholderText( tr("Hex value") );
    mAPublicKeyText->setPlaceholderText( tr( "Hex value" ) );
    mBPrivateKeyText->setPlaceholderText( tr("Hex value") );
    mBPublicKeyText->setPlaceholderText( tr("Hex value") );
    mAECDHPriKeyText->setPlaceholderText( tr("Hex value") );
    mAECDHPubKeyText->setPlaceholderText( tr("Hex value") );
    mBECDHPriKeyText->setPlaceholderText( tr("Hex value") );
    mBECDHPubKeyText->setPlaceholderText( tr("Hex value") );


    mParamLenCombo->addItems( sParamList );
    mParamLenCombo->setCurrentIndex(2);
    mTabWidget->setCurrentIndex(0);
}

void KeyAgreeDlg::genDHParam()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};

    int nLen = mParamLenCombo->currentText().toInt();
    int nG = mGCombo->currentText().toInt();

    ret = JS_PKI_genDHParam( nLen, nG, &binP, &binG, &binQ );
    if( ret == 0 )
    {
        mPText->setPlainText( getHexString( binP.pVal, binP.nLen));

        berApplet->log( "-- Genreate DH parameter" );
        berApplet->log( QString( "Length : %1").arg( mParamLenCombo->currentText()));
        berApplet->log( QString( "P      : %1").arg(getHexString( &binP)));
        berApplet->log( QString( "G      : %1").arg(getHexString( &binG)));
        if( binQ.nLen > 0 ) berApplet->log( QString( "Q      : %1" ).arg( getHexString( &binQ )));
    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binQ );
    update();
}

void KeyAgreeDlg::exportDHParam()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binParam = {0,0};

    ExportDlg exportDlg;

    if( mPText->toPlainText().length() < 1 )
    {
        berApplet->warningBox( tr( "Parameter value is required" ), this );
        mPText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGCombo->currentText().toStdString().c_str(), &binG );

    ret = JS_PKI_encodeDHParam( &binP, &binG, NULL, &binParam );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to encode DH param: %1").arg( ret ));
        goto end;
    }

    exportDlg.setDHParam( &binParam );
    exportDlg.setName( "DH_param" );
    exportDlg.exec();

end :
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binParam );
}

void KeyAgreeDlg::importDHParam()
{
    int ret = 0;
    BIN binParam = {0,0};
    BIN binP = {0,0};
    BIN binG = {0,0};

    QString strPath = berApplet->curFilePath();
    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_DH_PARAM, strPath );
    if( strFileName.length() < 1 ) return;

    ret = JS_BIN_fileReadBER( strFileName.toLocal8Bit().toStdString().c_str(), &binParam );
    if( ret <= 0 )
    {
        berApplet->elog( QString( "fail to read parameters: %1" ).arg( ret ));
        goto end;
    }

    ret = JS_PKI_decodeDHParam( &binParam, &binP, &binG, NULL );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to decode DH parameters: %1").arg( ret ), this );
        goto end;
    }

    mPText->setPlainText( getHexString( &binP ));
    mGCombo->setCurrentText( getHexString( &binG ));

end :
    JS_BIN_reset( &binParam );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
}

void KeyAgreeDlg::genADHPri()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = mParamLenCombo->currentText().toInt();
    nLen = nLen / 8;

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mAPrivateKeyText->setText( pHex );

    berApplet->log( "-- Generate DH A PrivateKey");
    berApplet->log( QString( "A PrivteKey : %1").arg( pHex ));

    if( pHex ) JS_free( pHex );
    update();
}

void KeyAgreeDlg::genBDHPri()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = mParamLenCombo->currentText().toInt();
    nLen = nLen / 8;

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mBPrivateKeyText->setText( pHex );

    berApplet->log( "-- Generate DH B PrivateKey");
    berApplet->log( QString( "B PrivteKey : %1").arg( pHex ));

    if( pHex ) JS_free( pHex );
    update();
}

void KeyAgreeDlg::genADHKey()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    if( mPText->toPlainText().length() < 1 )
    {
        berApplet->warningBox( tr( "Parameter value is required" ), this );
        mPText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGCombo->currentText().toStdString().c_str(), &binG );

    JS_BIN_decodeHex( mAPrivateKeyText->text().toStdString().c_str(), &binPri );

    if( binPri.nLen > 0 )
    {
        ret = JS_PKI_genDHPub( &binP, &binG, &binPri, &binPub );
        if( ret == 0 )
        {
            berApplet->log( "-- Generate DH A PublicKey");
        }
    }
    else
    {
        ret = JS_PKI_genDHKey( &binP, &binG, &binPri, &binPub );

        if( ret == 0 )
        {
            mAPrivateKeyText->setText( getHexString( binPri.pVal, binPri.nLen ));
            berApplet->log( "-- Generate DH A KeyPair");
            berApplet->log( QString( "A PrivateKey : %1").arg( getHexString( binPub.pVal, binPub.nLen) ));
        }
    }

    if( ret == 0 )
    {
        mAPublicKeyText->setText( getHexString( binPub.pVal, binPub.nLen ));
        berApplet->log( QString( "A PublicKey  : %1").arg( getHexString( binPub.pVal, binPub.nLen) ));
    }
    else
    {
        berApplet->elog( QString( "Key generation failed : %1" ).arg(ret));
    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    update();
}

void KeyAgreeDlg::genBDHKey()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    if( mPText->toPlainText().length() < 1 )
    {
        berApplet->warningBox( tr( "Parameter value is required" ), this );
        mPText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGCombo->currentText().toStdString().c_str(), &binG );

    JS_BIN_decodeHex( mBPrivateKeyText->text().toStdString().c_str(), &binPri );

    if( binPri.nLen > 0 )
    {
        ret = JS_PKI_genDHPub( &binP, &binG, &binPri, &binPub );
        if( ret == 0 )
        {
            berApplet->log( "-- Generate DH B PublicKey");
        }
    }
    else
    {
        ret = JS_PKI_genDHKey( &binP, &binG, &binPri, &binPub );

        if( ret == 0 )
        {
            mBPrivateKeyText->setText( getHexString( binPri.pVal, binPri.nLen ));
            berApplet->log( "-- Generate DH B KeyPair");
            berApplet->log( QString( "B PrivateKey : %1").arg( getHexString( binPub.pVal, binPub.nLen) ));
        }
    }

    if( ret == 0 )
    {
        mBPublicKeyText->setText( getHexString( binPub.pVal, binPub.nLen ));
        berApplet->log( QString( "B PublicKey  : %1").arg( getHexString( binPub.pVal, binPub.nLen) ));
    }
    else
    {
        berApplet->elog( QString( "Key generation failed : %1" ).arg(ret));
    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    update();
}

void KeyAgreeDlg::genAKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    JECKeyVal sKeyVal;
    QString strPub;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    QString strParam = mECDHParamCombo->currentText();

    ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    strPub = sKeyVal.pPubX;
    strPub += sKeyVal.pPubY;

    berApplet->log( "-- Generate ECDH A KeyPair");
    berApplet->log( QString( "ECDH A PrivateKey : %1").arg( sKeyVal.pPrivate ));
    berApplet->log( QString( "ECDH A PublicKey  : %1").arg( strPub ));

    mAECDHPriKeyText->setText( sKeyVal.pPrivate );
    mAECDHPubKeyText->setText( strPub );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetECKeyVal( &sKeyVal );
}

void KeyAgreeDlg::genBKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    JECKeyVal sKeyVal;
    QString strPub;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    QString strParam = mECDHParamCombo->currentText();

    ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    strPub = sKeyVal.pPubX;
    strPub += sKeyVal.pPubY;

    berApplet->log( "-- Generate ECDH B KeyPair");
    berApplet->log( QString( "ECDH B PrivateKey : %1").arg( sKeyVal.pPrivate ));
    berApplet->log( QString( "ECDH B PublicKey  : %1").arg( strPub ));

    mBECDHPriKeyText->setText( sKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetECKeyVal( &sKeyVal );
}

void KeyAgreeDlg::checkAPubKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binX = {0,0};
    BIN binY = {0,0};

    QString strParam = mECDHParamCombo->currentText();

    JS_BIN_decodeHex( mAECDHPubKeyText->text().toStdString().c_str(), &binPub );

    JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
    JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binX, &binY );
    if( ret == 1 )
        berApplet->messageBox( tr("The public key is correct"), this );
    else
        berApplet->warningBox( tr("The public key is incorrect"), this );

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binX );
    JS_BIN_reset( &binY );
}

void KeyAgreeDlg::checkBPubKey()
{
    int ret = 0;
    BIN binPub = {0,0};
    BIN binX = {0,0};
    BIN binY = {0,0};

    QString strParam = mECDHParamCombo->currentText();

    JS_BIN_decodeHex( mBECDHPubKeyText->text().toStdString().c_str(), &binPub );

    JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
    JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binX, &binY );
    if( ret == 1 )
        berApplet->messageBox( tr("The public key is correct"), this );
    else
        berApplet->warningBox( tr("The public key is incorrect"), this );

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binX );
    JS_BIN_reset( &binY );
}

void KeyAgreeDlg::checkAKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binX = {0,0};
    BIN binY = {0,0};

    QString strParam = mECDHParamCombo->currentText();

    JS_BIN_decodeHex( mAECDHPubKeyText->text().toStdString().c_str(), &binPub );
    JS_BIN_decodeHex( mAECDHPriKeyText->text().toStdString().c_str(), &binPri );

    JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
    JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);


    ret = JS_PKI_IsValidECCKeyPairValue( strParam.toStdString().c_str(), &binPri, &binX, &binY );
    if( ret == 1 )
        berApplet->messageBox( tr("The key pair is correct"), this );
    else
        berApplet->warningBox( tr("The key pair is incorrect"), this );

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binX );
    JS_BIN_reset( &binY );
    JS_BIN_reset( &binPri );
}

void KeyAgreeDlg::checkBKeyPair()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binX = {0,0};
    BIN binY = {0,0};

    QString strParam = mECDHParamCombo->currentText();

    JS_BIN_decodeHex( mBECDHPubKeyText->text().toStdString().c_str(), &binPub );
    JS_BIN_decodeHex( mBECDHPriKeyText->text().toStdString().c_str(), &binPri );

    JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
    JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);


    ret = JS_PKI_IsValidECCKeyPairValue( strParam.toStdString().c_str(), &binPri, &binX, &binY );
    if( ret == 1 )
        berApplet->messageBox( tr("The key pair is correct"), this );
    else
        berApplet->warningBox( tr("The key pair is incorrect"), this );

    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binX );
    JS_BIN_reset( &binY );
    JS_BIN_reset( &binPri );
}

void KeyAgreeDlg::genAECDHPriKey()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = JS_PKI_getECKeyLen( mECDHParamCombo->currentText().toStdString().c_str() );

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );

    berApplet->log( "-- ECDH A Private" );
    berApplet->log( QString( "ECDH A PrivateKey : %1" ).arg( pHex ));

    mAECDHPriKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );

    update();
}

void KeyAgreeDlg::genAECDHPubKey()
{
    BIN binAPri = {0,0};
    BIN binAPubX = {0,0};
    BIN binAPubY = {0,0};
    QString strPub;

    if( mAECDHPriKeyText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "A private key value is required" ), this );
        mAECDHPriKeyText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mAECDHPriKeyText->text().toStdString().c_str(), &binAPri );
    JS_PKI_genECPubKey( mECDHParamCombo->currentText().toStdString().c_str(), &binAPri, &binAPubX, &binAPubY );

    strPub = getHexString( binAPubX.pVal, binAPubX.nLen );
    strPub += getHexString( binAPubY.pVal, binAPubY.nLen );

    berApplet->log( "-- ECDH A Public" );
    berApplet->log( QString( "ECDH A PublicKey : %1" ).arg( strPub ));

    mAECDHPubKeyText->setText( strPub );

    JS_BIN_reset( &binAPri );
    JS_BIN_reset( &binAPubX );
    JS_BIN_reset( &binAPubY );

    update();
}

void KeyAgreeDlg::findAECDHPriKey()
{
    BIN binECKey = {0,0};
    JECKeyVal sECKeyVal;
    int nKeyType = -1;

    const char  *pSN = NULL;

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    QString strPath;
    QString strPub;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    JS_BIN_fileRead( fileName.toLocal8Bit().toStdString().c_str(), &binECKey );
    nKeyType = JS_PKI_getPriKeyType( &binECKey );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binECKey, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mAECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mAECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binECKey );
    JS_PKI_resetECKeyVal( &sECKeyVal );
    update();
}

void KeyAgreeDlg::getAFromCertMan()
{
    int nKeyType = -1;
    BIN binPri = {0,0};
    JECKeyVal sECKeyVal;
    const char  *pSN = NULL;
    QString strPub;

    CertManDlg certMan;
    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a certificate") );
    certMan.mKeyTypeCombo->setCurrentText( "ECDSA" );

    if( certMan.exec() != QDialog::Accepted )
        return;

    certMan.getPriKey( &binPri );

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mAECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mAECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sECKeyVal );
}

void KeyAgreeDlg::getAFromKeyPair()
{
    int nKeyType = -1;
    BIN binPri = {0,0};
    JECKeyVal sECKeyVal;
    const char  *pSN = NULL;
    QString strPath;
    QString strPub;


    KeyPairManDlg keyPairMan;
    keyPairMan.setMode( KeyPairModeSelect );
    keyPairMan.setTitle( tr( "Select keypair") );
    keyPairMan.mKeyTypeCombo->setCurrentText( "ECDSA" );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    strPath = keyPairMan.getPriPath();

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binPri );
    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mAECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mAECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sECKeyVal );
}

void KeyAgreeDlg::genBECDHPriKey()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = JS_PKI_getECKeyLen( mECDHParamCombo->currentText().toStdString().c_str() );

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );

    berApplet->log( "-- ECDH B Private" );
    berApplet->log( QString( "ECDH B PrivateKey : %1" ).arg( pHex ));

    mBECDHPriKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );
    update();
}

void KeyAgreeDlg::genBECDHPubKey()
{
    BIN binPri = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    QString strPub;

    if( mBECDHPriKeyText->text().length() < 1 )
    {
        berApplet->warningBox( tr( "B private key value is required" ), this );
        mBECDHPriKeyText->setFocus();
        return;
    }

    JS_BIN_decodeHex( mBECDHPriKeyText->text().toStdString().c_str(), &binPri );
    JS_PKI_genECPubKey( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binPubX, &binPubY );

    strPub = getHexString( binPubX.pVal, binPubX.nLen );
    strPub += getHexString( binPubY.pVal, binPubY.nLen );

    berApplet->log( "-- ECDH B Public" );
    berApplet->log( QString( "ECDH B PublicKey : %1" ).arg( strPub ));

    mBECDHPubKeyText->setText( strPub );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    update();
}

void KeyAgreeDlg::findBECDHPriKey()
{
    BIN binECKey = {0,0};
    JECKeyVal sECKeyVal;
    int nKeyType = -1;

    const char  *pSN = NULL;

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    QString strPath;
    QString strPub;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    JS_BIN_fileRead( fileName.toLocal8Bit().toStdString().c_str(), &binECKey );
    nKeyType = JS_PKI_getPriKeyType( &binECKey );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binECKey, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mBECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binECKey );
    JS_PKI_resetECKeyVal( &sECKeyVal );
    update();
}

void KeyAgreeDlg::getBFromCertMan()
{
    int nKeyType = -1;
    BIN binPri = {0,0};
    JECKeyVal sECKeyVal;
    const char  *pSN = NULL;
    QString strPub;

    CertManDlg certMan;
    certMan.setMode( ManModeSelBoth );
    certMan.setTitle( tr( "Select a certificate") );
    certMan.mKeyTypeCombo->setCurrentText( "ECDSA" );

    if( certMan.exec() != QDialog::Accepted )
        return;

    certMan.getPriKey( &binPri );

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mBECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sECKeyVal );
}

void KeyAgreeDlg::getBFromKeyPair()
{
    int nKeyType = -1;
    BIN binPri = {0,0};
    JECKeyVal sECKeyVal;
    const char  *pSN = NULL;
    QString strPath;
    QString strPub;


    KeyPairManDlg keyPairMan;
    keyPairMan.setMode( KeyPairModeSelect );
    keyPairMan.setTitle( tr( "Select keypair") );
    keyPairMan.mKeyTypeCombo->setCurrentText( "ECDSA" );

    if( keyPairMan.exec() != QDialog::Accepted )
        return;

    strPath = keyPairMan.getPriPath();

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binPri );
    nKeyType = JS_PKI_getPriKeyType( &binPri );

    if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 )
    {
        berApplet->warningBox( tr("Invalid PrivateKey Type: %1").arg( nKeyType ), this);
        goto end;
    }

    JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
    pSN = JS_PKI_getSNFromOID( sECKeyVal.pCurveOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mBECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );

end :
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sECKeyVal );
}

void KeyAgreeDlg::pChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mPText->toPlainText() );
    mPLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::APriKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mAPrivateKeyText->text() );
    mAPrivateKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::APubKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mAPublicKeyText->text() );
    mAPublicKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::BPriKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mBPrivateKeyText->text() );
    mBPrivateKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::BPubKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mBPublicKeyText->text() );
    mBPublicKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::AECDHPriKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mAECDHPriKeyText->text() );
    mAECDHPriKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::AECDHPubKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mAECDHPubKeyText->text() );
    mAECDHPubKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::BECDHPriKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mBECDHPriKeyText->text() );
    mBECDHPriKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::BECDHPubKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mBECDHPubKeyText->text() );
    mBECDHPubKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::secretKeyChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mSecretKeyText->toPlainText() );
    mSecretKeyLenText->setText( QString("%1").arg(strLen));
}

void KeyAgreeDlg::changeECDHParam( int index )
{
    char sOID[1024];

    memset(sOID, 0x00, sizeof(sOID));

    QString strSN = mECDHParamCombo->currentText();
    JS_PKI_getOIDFromSN( strSN.toStdString().c_str(), sOID );

    mECDHParamText->setText( sOID );
}

void KeyAgreeDlg::clickClearDataAll()
{
    mPText->clear();
    mAPrivateKeyText->clear();
    mAPublicKeyText->clear();
    mBPrivateKeyText->clear();
    mBPublicKeyText->clear();

    mAECDHPriKeyText->clear();
    mAECDHPubKeyText->clear();
    mBECDHPriKeyText->clear();
    mBECDHPubKeyText->clear();

    mSecretKeyText->clear();
}
