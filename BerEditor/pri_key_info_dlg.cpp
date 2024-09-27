/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "js_pki_key.h"

#include "ber_applet.h"
#include "pri_key_info_dlg.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "js_error.h"
#include "common.h"


PriKeyInfoDlg::PriKeyInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    key_type_ = -1;

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

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

    connect( mDSA_GText, SIGNAL(textChanged()), this, SLOT(changeDSA_G()));
    connect( mDSA_PText, SIGNAL(textChanged()), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q(const QString&)));
    connect( mDSA_PublicText, SIGNAL(textChanged()), this, SLOT(changeDSA_Public()));
    connect( mDSA_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Private(const QString&)));

    connect( mEdDSA_RawPublicText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPublic()));
    connect( mEdDSA_RawPrivateText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPrivate()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));
    connect( mCheckPubKeyBtn, SIGNAL(clicked()), this, SLOT(clickCheckPubKey()));

    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mApplyChangeBtn, SIGNAL(clicked()), this, SLOT(clickApplyChange()));
    connect( mSavePriKeyBtn, SIGNAL(clicked()), this, SLOT(clickSavePriKey()));
    connect( mSavePubKeyBtn, SIGNAL(clicked()), this, SLOT(clickSavePubKey()));
    connect( mEditModeCheck, SIGNAL(clicked()), this, SLOT(checkEditMode()));

    initialize();
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    tabRSA->layout()->setSpacing(5);
    tabRSA->layout()->setMargin(5);
    tabECC->layout()->setSpacing(5);
    tabECC->layout()->setMargin(5);
    tabDSA->layout()->setSpacing(5);
    tabDSA->layout()->setMargin(5);
    tabEdDSA->layout()->setSpacing(5);
    tabEdDSA->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PriKeyInfoDlg::~PriKeyInfoDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
}

void PriKeyInfoDlg::initialize()
{
    mKeyTab->setTabEnabled(0, false);
    mKeyTab->setTabEnabled(1, false);
    mKeyTab->setTabEnabled(2, false);
    mKeyTab->setTabEnabled(3, false);
}

bool PriKeyInfoDlg::isChanged()
{
    if( key_type_ < 0 ) return true;

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKey;
        memset( &sRSAKey, 0x00, sizeof(sRSAKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getRSAKeyVal( &pri_key_, &sRSAKey );
        else
            JS_PKI_getRSAKeyValFromPub( &pub_key_, &sRSAKey );

        if( mRSA_EText->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pE ) )
            return true;

        if( mRSA_NText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pN ) )
            return true;

        if( pri_key_.nLen > 0 )
        {
            if( mRSA_DText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pD ) )
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_DMP1Text->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pDMP1 ))
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_DMQ1Text->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pDMQ1) )
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }

            if( mRSA_IQMPText->text().simplified().toUpper() != QString( "%1" ).arg( sRSAKey.pIQMP ))
            {
                JS_PKI_resetRSAKeyVal( &sRSAKey );
                return true;
            }
        }

        JS_PKI_resetRSAKeyVal( &sRSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECC || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        JECKeyVal sECKey;
        memset( &sECKey, 0x00, sizeof(sECKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getECKeyVal( &pri_key_, &sECKey );
        else
            JS_PKI_getECKeyValFromPub( &pub_key_, &sECKey );

        if( mECC_PubXText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPubX ))
        {
            JS_PKI_resetECKeyVal( &sECKey );
            return true;
        }

        if( mECC_PubYText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPubY ))
        {
            JS_PKI_resetECKeyVal( &sECKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mECC_PrivateText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sECKey.pPrivate ))
            {
                JS_PKI_resetECKeyVal( &sECKey );
                return true;
            }
        }

        JS_PKI_resetECKeyVal( &sECKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        JDSAKeyVal sDSAKey;
        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getDSAKeyVal( &pri_key_, &sDSAKey );
        else
            JS_PKI_getDSAKeyValFromPub( &pub_key_, &sDSAKey );

        if( mDSA_QText->text().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pQ ) )
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_GText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pG ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_PText->toPlainText().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pP ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( mDSA_PublicText->toPlainText().simplified().toUpper() != QString("%1").arg( sDSAKey.pPublic ))
        {
            JS_PKI_resetDSAKeyVal( &sDSAKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mDSA_PrivateText->text().simplified().toUpper() != QString( "%1" ).arg( sDSAKey.pPrivate ))
            {
                JS_PKI_resetDSAKeyVal( &sDSAKey );
                return true;
            }
        }

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ED25519 || key_type_ == JS_PKI_KEY_TYPE_ED448 )
    {
        JRawKeyVal sRawKey;
        memset( &sRawKey, 0x00, sizeof(sRawKey));

        if( pri_key_.nLen > 0 )
            JS_PKI_getRawKeyVal( key_type_, &pri_key_, &sRawKey );
        else
            JS_PKI_getRawKeyValFromPub( key_type_, &pub_key_, &sRawKey );

        if( mEdDSA_RawPublicText->toPlainText().simplified().toUpper() != QString("%1").arg( sRawKey.pPub ) )
        {
            JS_PKI_resetRawKeyVal( &sRawKey );
            return true;
        }

        if( pri_key_.nLen > 0 )
        {
            if( mEdDSA_RawPrivateText->toPlainText().simplified().toUpper() != QString("%1").arg( sRawKey.pPri ))
            {
                JS_PKI_resetRawKeyVal( &sRawKey );
                return true;
            }
        }

        JS_PKI_resetRawKeyVal( &sRawKey );
    }

    return false;
}

void PriKeyInfoDlg::showEvent(QShowEvent *event)
{

}

void PriKeyInfoDlg::setRSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    if( bPri == true )
        ret = JS_PKI_getRSAKeyVal( pKey, &sRSAKey );
    else
        ret = JS_PKI_getRSAKeyValFromPub( pKey, &sRSAKey );

    if( ret == 0 )
    {
        mRSA_NText->setPlainText( sRSAKey.pN );
        mRSA_EText->setText( sRSAKey.pE );
        mRSA_DText->setPlainText( sRSAKey.pD );
        mRSA_PText->setText( sRSAKey.pP );
        mRSA_QText->setText( sRSAKey.pQ );
        mRSA_DMP1Text->setText( sRSAKey.pDMP1 );
        mRSA_DMQ1Text->setText( sRSAKey.pDMQ1 );
        mRSA_IQMPText->setText( sRSAKey.pIQMP );
    }

    JS_PKI_resetRSAKeyVal( &sRSAKey );
}

void PriKeyInfoDlg::setECCKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JECKeyVal sECKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey));

    if( bPri == true )
        ret = JS_PKI_getECKeyVal( pKey, &sECKey );
    else
        ret = JS_PKI_getECKeyValFromPub( pKey, &sECKey );

    if( ret == 0 )
    {
        QString strSN = JS_PKI_getSNFromOID( sECKey.pCurveOID );
        mECC_CurveOIDText->setText( sECKey.pCurveOID );
        mECC_CurveSNText->setText( strSN );

        mECC_PubXText->setPlainText( sECKey.pPubX );
        mECC_PubYText->setPlainText( sECKey.pPubY );
        mECC_PrivateText->setPlainText( sECKey.pPrivate );
    }

    JS_PKI_resetECKeyVal( &sECKey );
}

void PriKeyInfoDlg::setDSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JDSAKeyVal sDSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    if( bPri == true )
        ret = JS_PKI_getDSAKeyVal( pKey, &sDSAKey );
    else
        ret = JS_PKI_getDSAKeyValFromPub( pKey, &sDSAKey );

    if( ret == 0 )
    {
        mDSA_GText->setPlainText( sDSAKey.pG );
        mDSA_PText->setPlainText( sDSAKey.pP );
        mDSA_QText->setText( sDSAKey.pQ );
        mDSA_PublicText->setPlainText( sDSAKey.pPublic );
        mDSA_PrivateText->setText( sDSAKey.pPrivate );
    }

    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void PriKeyInfoDlg::setEdDSAKey( int nKeyType, const BIN *pKey, bool bPri )
{
    int ret = 0;
    JRawKeyVal sRawKeyVal;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sRawKeyVal, 0x00, sizeof(sRawKeyVal));

    if( bPri == true )
        ret = JS_PKI_getRawKeyVal( nKeyType, pKey, &sRawKeyVal );
    else
        ret = JS_PKI_getRawKeyValFromPub( nKeyType, pKey, &sRawKeyVal );

    if( ret == 0 )
    {
        mEdDSA_NameText->setText( sRawKeyVal.pName );
        mEdDSA_RawPublicText->setPlainText( sRawKeyVal.pPub );
        mEdDSA_RawPrivateText->setPlainText( sRawKeyVal.pPri );
    }

    JS_PKI_resetRawKeyVal( &sRawKeyVal );
}

void PriKeyInfoDlg::changeRSA_N()
{
    QString strN = mRSA_NText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strN );
    mRSA_NLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_E( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_ELenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_D()
{
    QString strD = mRSA_DText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strD );
    mRSA_DLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_P( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMP1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMP1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMQ1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMQ1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_IQMP( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_IQMPLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubX()
{
    QString strPubX = mECC_PubXText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubX );
    mECC_PubXLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubY()
{
    QString strPubY = mECC_PubYText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubY );
    mECC_PubYLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_Private()
{
    QString strPrivate = mECC_PrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPrivate );
    mECC_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_G()
{
    QString strG = mDSA_GText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strG );
    mDSA_GLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_P()
{
    QString strP = mDSA_PText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strP );
    mDSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Public()
{
    QString strPublic = mDSA_PublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPublic );
    mDSA_PublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Private( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPublic()
{
    QString strRawPublic = mEdDSA_RawPublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPublic );
    mEdDSA_RawPublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPrivate()
{
    QString strRawPrivte = mEdDSA_RawPrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPrivte );
    mEdDSA_RawPrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::clearAll()
{
    mRSA_DText->clear();
    mRSA_EText->clear();
    mRSA_NText->clear();
    mRSA_PText->clear();
    mRSA_QText->clear();
    mRSA_DMP1Text->clear();
    mRSA_DMQ1Text->clear();
    mRSA_IQMPText->clear();

    mECC_PubXText->clear();
    mECC_PubYText->clear();
    mECC_CurveOIDText->clear();
    mECC_PrivateText->clear();

    mDSA_GText->clear();
    mDSA_PText->clear();
    mDSA_QText->clear();
    mDSA_PublicText->clear();
    mDSA_PrivateText->clear();

    mEdDSA_NameText->clear();
    mEdDSA_RawPublicText->clear();
    mEdDSA_RawPrivateText->clear();
}

void PriKeyInfoDlg::clickDecode()
{
    if( mEditModeCheck->isChecked() == true )
    {
        berApplet->warningBox( tr( "Not available in edit mode" ), this );
        return;
    }

    if( pri_key_.nLen > 0 )
        berApplet->decodeData( &pri_key_, NULL );
    else
        berApplet->decodeData( &pub_key_, NULL );
}

void PriKeyInfoDlg::clickCheckPubKey()
{
    if( mEditModeCheck->isChecked() == true )
    {
        berApplet->warningBox( tr( "Not available in edit mode" ), this );
        return;
    }

    int ret = 0;
    if( pub_key_.nLen > 0 )
    {
        ret = JS_PKI_checkPublicKey( &pub_key_ );
    }
    else
    {
        BIN binPub = {0,0};
        JS_PKI_getPubKeyFromPriKey( key_type_, &pri_key_, &binPub );
        ret = JS_PKI_checkPublicKey( &binPub );
        JS_BIN_reset( &binPub );
    }

    if( ret == JSR_VALID )
        berApplet->messageBox( tr( "PublicKey is valid" ), this );
    else
        berApplet->warningBox( tr( "PublicKey is invalid" ), this );
}

void PriKeyInfoDlg::clickSavePriKey()
{
    if( mEditModeCheck->isChecked() == true )
    {
        berApplet->warningBox( tr( "Not available in edit mode" ), this );
        return;
    }

    QString strPath = berApplet->curFolder();
    QString strAlg = JS_PKI_getKeyTypeName( key_type_ );

    if( strPath.length() > 0 ) strPath += "/";
    strPath = QString( "%1%2_private_key.pem" ).arg( strPath ).arg(strAlg);

    QString fileName = findSaveFile( this, JS_FILE_TYPE_BER, strPath );

    if( fileName.length() > 0 )
    {
        int ret = JS_BIN_writePEM( &pri_key_, JS_PEM_TYPE_PRIVATE_KEY, fileName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Save a private key as a PEM file" ), this );
        }
    }
}

void PriKeyInfoDlg::clickSavePubKey()
{
    if( mEditModeCheck->isChecked() == true )
    {
        berApplet->warningBox( tr( "Not available in edit mode" ), this );
        return;
    }

    BIN binPub = {0,0};

    if( pri_key_.nLen > 0 )
        JS_PKI_getPubKeyFromPriKey( key_type_, &pri_key_, &binPub );
    else
        JS_BIN_copy( &binPub, &pub_key_ );

    QString strPath = berApplet->curFolder();
    QString strAlg = JS_PKI_getKeyTypeName( key_type_ );

    if( strPath.length() > 0 ) strPath += "/";
    strPath = QString( "%1%2_public_key.pem" ).arg( strPath ).arg(strAlg);

    QString fileName = findSaveFile( this, JS_FILE_TYPE_BER, strPath );



    if( fileName.length() > 0 )
    {
        int ret = JS_BIN_writePEM( &pri_key_, JS_PEM_TYPE_PUBLIC_KEY, fileName.toLocal8Bit().toStdString().c_str() );
        if( ret > 0 )
        {
            berApplet->messageBox( tr( "Save a public key as a PEM file" ), this );
        }
    }

    JS_BIN_reset( &binPub );
}

void PriKeyInfoDlg::clickCheckKeyPair()
{
    if( mEditModeCheck->isChecked() == true )
    {
        berApplet->warningBox( tr( "Not available in edit mode" ), this );
        return;
    }

    BIN binPub = {0,0};

    int ret = JS_PKI_getPubKeyFromPriKey( key_type_, &pri_key_, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_IsValidKeyPair( &pri_key_, &binPub );
    if( ret == 1 )
        ret = JSR_VALID;

end :
    if( ret == JSR_VALID )
        berApplet->messageBox( tr( "KeyPair is matched" ), this );
    else
        berApplet->warningBox( tr( "KeyPais is not matched" ), this );

    JS_BIN_reset( &binPub );
}

void PriKeyInfoDlg::clickApplyChange()
{
    int ret = 0;
    BIN binKey = {0,0};

    bool bVal = berApplet->yesOrCancelBox( tr("Do you want to save the key value?"), this, false );
    if( bVal == false ) return;

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKey;

        memset( &sRSAKey, 0x00, sizeof(sRSAKey));

        JS_PKI_setRSAKeyVal( &sRSAKey,
                            mRSA_NText->toPlainText().toStdString().c_str(),
                            mRSA_EText->text().toStdString().c_str(),
                            mRSA_DText->toPlainText().toStdString().c_str(),
                            mRSA_PText->text().toStdString().c_str(),
                            mRSA_QText->text().toStdString().c_str(),
                            mRSA_DMP1Text->text().toStdString().c_str(),
                            mRSA_DMQ1Text->text().toStdString().c_str(),
                            mRSA_IQMPText->text().toStdString().c_str() );

        if( pri_key_.nLen > 0 )
        {
            ret = JS_PKI_encodeRSAPrivateKey( &sRSAKey, &binKey );
        }
        else
        {
            ret = JS_PKI_encodeRSAPublicKey( &sRSAKey, &binKey );
        }

        JS_PKI_resetRSAKeyVal( &sRSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECC || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        JECKeyVal sECKey;

        memset( &sECKey, 0x00, sizeof(sECKey));

        JS_PKI_setECKeyVal( &sECKey,
                           mECC_CurveOIDText->text().toStdString().c_str(),
                           mECC_PubXText->toPlainText().toStdString().c_str(),
                           mECC_PubYText->toPlainText().toStdString().c_str(),
                           mECC_PrivateText->toPlainText().toStdString().c_str() );

        if( pri_key_.nLen > 0 )
        {
            ret = JS_PKI_encodeECPrivateKey( &sECKey, &binKey );
        }
        else
        {
            ret = JS_PKI_encodeECPublicKey( &sECKey, &binKey );
        }

        JS_PKI_resetECKeyVal( &sECKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        JDSAKeyVal sDSAKey;

        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        JS_PKI_setDSAKeyVal( &sDSAKey,
                            mDSA_GText->toPlainText().toStdString().c_str(),
                            mDSA_PText->toPlainText().toStdString().c_str(),
                            mDSA_QText->text().toStdString().c_str(),
                            mDSA_PublicText->toPlainText().toStdString().c_str(),
                            mDSA_PrivateText->text().toStdString().c_str() );

        if( pri_key_.nLen > 0 )
        {
            ret = JS_PKI_encodeDSAPrivateKey( &sDSAKey, &binKey );
        }
        else
        {
            ret = JS_PKI_encodeDSAPublicKey( &sDSAKey, &binKey );
        }

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ED25519 || key_type_ == JS_PKI_KEY_TYPE_ED448 )
    {
        JRawKeyVal sRawKey;

        memset( &sRawKey, 0x00, sizeof(sRawKey));

        JS_PKI_setRawKeyVal( &sRawKey,
                            mEdDSA_RawPublicText->toPlainText().toStdString().c_str(),
                            mEdDSA_RawPrivateText->toPlainText().toStdString().c_str(),
                            mEdDSA_NameText->text().toStdString().c_str() );

        if( pri_key_.nLen > 0 )
        {
            ret = JS_PKI_encodeRawPrivateKey( &sRawKey, &binKey );
        }
        else
        {
            ret = JS_PKI_encodeRawPublicKey( &sRawKey, &binKey );
        }

        JS_PKI_resetRawKeyVal( &sRawKey );
    }

    if( ret == 0 )
    {
        berApplet->messageBox( tr( "Key value change was successful" ), this );
        if( pri_key_.nLen > 0 )
        {
            JS_BIN_reset( &pri_key_ );
            JS_BIN_copy( &pri_key_, &binKey );
        }
        else
        {
            JS_BIN_reset( &pub_key_ );
            JS_BIN_copy( &pub_key_, &binKey );
        }

        mEditModeCheck->setChecked( false );
        mApplyChangeBtn->setEnabled( false );
        setModeUI( false );
    }
    else
    {
        berApplet->warningBox( tr( "fail to apply change: %1").arg( ret ), this );
    }

    JS_BIN_reset( &binKey );
}

void PriKeyInfoDlg::setModeUI( bool bVal )
{
    QString strStyle;

    if( bVal == true )
        strStyle = "background-color:#FFFFFF";
    else
        strStyle = "background-color:#ddddff";

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mRSA_EText->setStyleSheet( strStyle );
        mRSA_EText->setReadOnly(!bVal);
        mRSA_NText->setStyleSheet( strStyle );
        mRSA_NText->setReadOnly(!bVal);

        if( pri_key_.nLen > 0 )
        {
            mRSA_DText->setStyleSheet( strStyle );
            mRSA_DText->setReadOnly(!bVal);
            mRSA_PText->setStyleSheet( strStyle );
            mRSA_PText->setReadOnly(!bVal);
            mRSA_QText->setStyleSheet( strStyle );
            mRSA_QText->setReadOnly(!bVal);
            mRSA_DMP1Text->setStyleSheet( strStyle );
            mRSA_DMP1Text->setReadOnly(!bVal);
            mRSA_DMQ1Text->setStyleSheet( strStyle );
            mRSA_DMQ1Text->setReadOnly(!bVal);
            mRSA_IQMPText->setStyleSheet( strStyle );
            mRSA_IQMPText->setReadOnly(!bVal);
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECC || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mECC_PubXText->setStyleSheet( strStyle );
        mECC_PubXText->setReadOnly( !bVal );
        mECC_PubYText->setStyleSheet( strStyle );
        mECC_PubYText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mECC_PrivateText->setStyleSheet( strStyle );
            mECC_PrivateText->setReadOnly( !bVal );
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mDSA_GText->setStyleSheet( strStyle );
        mDSA_GText->setReadOnly( !bVal );
        mDSA_PText->setStyleSheet( strStyle );
        mDSA_PText->setReadOnly( !bVal );
        mDSA_QText->setStyleSheet( strStyle );
        mDSA_QText->setReadOnly( !bVal );
        mDSA_PublicText->setStyleSheet( strStyle );
        mDSA_PublicText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mDSA_PrivateText->setStyleSheet( strStyle );
            mDSA_PrivateText->setReadOnly( !bVal );
        }
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ED25519 || key_type_ == JS_PKI_KEY_TYPE_ED448 )
    {
        mEdDSA_RawPublicText->setStyleSheet( strStyle );
        mEdDSA_RawPublicText->setReadOnly( !bVal );

        if( pri_key_.nLen > 0 )
        {
            mEdDSA_RawPrivateText->setStyleSheet( strStyle );
            mEdDSA_RawPrivateText->setReadOnly( !bVal );
        }
    }
}

void PriKeyInfoDlg::checkEditMode()
{
    QString strStyle;

    bool bVal = mEditModeCheck->isChecked();
    mApplyChangeBtn->setEnabled( bVal );

    if( bVal == false )
    {
        if( isChanged() == false )
        {
            setModeUI( bVal );
            return;
        }

        if( berApplet->yesOrCancelBox(
                tr( "Would you like to revert to the state before editing?" ),
                this, true ) == false )
        {
            mEditModeCheck->setChecked(true);
            return;
        }

        BIN binKey = {0,0};
        if( pri_key_.nLen > 0 )
        {
            JS_BIN_copy( &binKey, &pri_key_ );
            JS_BIN_reset( &pri_key_ );
            setPrivateKey( &binKey );
        }
        else
        {
            JS_BIN_copy( &binKey, &pub_key_ );
            JS_BIN_reset( &pub_key_ );
            setPublicKey( &binKey );
        }
        JS_BIN_reset( &binKey );
    }

    setModeUI( bVal );
}

void PriKeyInfoDlg::setPrivateKey( const BIN *pPriKey )
{
    clearAll();

    QString strTitle = tr( "Private Key Information" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
    JS_BIN_copy( &pri_key_, pPriKey );


    if( pPriKey == NULL || pPriKey->nLen <= 0 )
        return;

    key_type_ = JS_PKI_getPriKeyType( pPriKey );
    if( key_type_ < 0 ) return;

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECC || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( pPriKey );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ED25519 || key_type_ == JS_PKI_KEY_TYPE_ED448 )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_type_, pPriKey );
    }
    else
    {
        berApplet->warningBox( tr("Private key algorithm(%1) not supported").arg( key_type_ ), this);
    }
}

void PriKeyInfoDlg::setPublicKey( const BIN *pPubKey )
{
    clearAll();

    QString strTitle = tr( "Public Key Information" );

    mTitleLabel->setText( strTitle );
    setWindowTitle( strTitle );

    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &pub_key_ );
    JS_BIN_copy( &pub_key_, pPubKey );

    if( pPubKey == NULL || pPubKey->nLen <= 0 )
        return;

    key_type_ = JS_PKI_getPubKeyType( pPubKey );

    if( key_type_ == JS_PKI_KEY_TYPE_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ECC || key_type_ == JS_PKI_KEY_TYPE_SM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( pPubKey, false );
    }
    else if( key_type_ == JS_PKI_KEY_TYPE_ED25519 || key_type_ == JS_PKI_KEY_TYPE_ED448  )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_type_, pPubKey, false );
    }
    else
    {
        berApplet->warningBox( tr("Public key algorithm(%1) not supported").arg( key_type_ ), this);
    }

    mCheckKeyPairBtn->setEnabled(false);
    mSavePriKeyBtn->setEnabled(false);
}

void PriKeyInfoDlg::readPrivateKey( BIN *pPriKey )
{
    if( pPriKey == NULL ) return;

    JS_BIN_copy( pPriKey, &pri_key_ );
}

void PriKeyInfoDlg::readPublicKey( BIN *pPubKey )
{
    if( pPubKey == NULL ) return;

    JS_BIN_copy( pPubKey, &pub_key_ );
}
