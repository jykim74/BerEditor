#include <QFileDialog>
#include <QDialogButtonBox>

#include "key_agree_dlg.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "common.h"
#include "ber_applet.h"


const QStringList sGList = { "0", "2", "5" };
const QStringList sECCParamList = {
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "prime256v1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1"
};


KeyAgreeDlg::KeyAgreeDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mGenParamBtn, SIGNAL(clicked()), this, SLOT(genDHParam()));
    connect( mADHPriBtn, SIGNAL(clicked()), this, SLOT(genADHPri()));
    connect( mBDHPriBtn, SIGNAL(clicked()), this, SLOT(genBDHPri()));
    connect( mAGenDHKeyBtn, SIGNAL(clicked()), this, SLOT(genADHKey()));
    connect( mBGenDHKeyBtn, SIGNAL(clicked()), this, SLOT(genBDHKey()));
    connect( mAGenPriKeyBtn, SIGNAL(clicked()), this, SLOT(genAECDHPriKey()));
    connect( mAGenPubKeyBtn, SIGNAL(clicked()), this, SLOT(genAECDHPubKey()));
    connect( mAFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findAECDHPriKey() ));
    connect( mBGenPriKeyBtn, SIGNAL(clicked()), this, SLOT(genBECDHPriKey()));
    connect( mBGenPubKeyBtn, SIGNAL(clicked()), this, SLOT(genBECDHPubKey()));
    connect( mBFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findBECDHPriKey()));
    connect( mAGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(genAKeyPair()));
    connect( mBGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(genBKeyPair()));

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

    initialize();
    mCloseBtn->setFocus();
}

KeyAgreeDlg::~KeyAgreeDlg()
{

}

void KeyAgreeDlg::calcualteA()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binSecret = {0,0};

    if( mTabWidget->currentIndex() == 0 )
    {
        BIN binP = {0,0};
        BIN binG = {0,0};


        JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
        JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );
        JS_BIN_decodeHex( mAPrivateKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mBPublicKeyText->text().toStdString().c_str(), &binPub );


        ret = JS_PKI_getDHSecret( &binP, &binG, &binPri, &binPub, &binSecret );

        JS_BIN_reset( &binP );
        JS_BIN_reset( &binG );
    }
    else
    {
        BIN binX = {0,0};
        BIN binY = {0,0};

        JS_BIN_decodeHex( mAECDHPriKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mBECDHPubKeyText->text().toStdString().c_str(), &binPub );

        JS_BIN_set( &binX, binPub.pVal, binPub.nLen / 2 );
        JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen / 2);
        ret = JS_PKI_getECDHSecretWithValue( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binX, &binY, &binSecret );

        JS_BIN_reset( &binX );
        JS_BIN_reset( &binY );
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binSecret, &pHex );
        mSecretKeyText->setPlainText(pHex);
        JS_free( pHex );
    }

    repaint();
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSecret );
}

void KeyAgreeDlg::calcualteB()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binSecret = {0,0};

    if( mTabWidget->currentIndex() == 0 )
    {
        BIN binP = {0,0};
        BIN binG = {0,0};


        JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
        JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );
        JS_BIN_decodeHex( mBPrivateKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mAPublicKeyText->text().toStdString().c_str(), &binPub );


        ret = JS_PKI_getDHSecret( &binP, &binG, &binPri, &binPub, &binSecret );

        JS_BIN_reset( &binP );
        JS_BIN_reset( &binG );
    }
    else
    {
        BIN binX = {0,0};
        BIN binY = {0,0};

        JS_BIN_decodeHex( mBECDHPriKeyText->text().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( mAECDHPubKeyText->text().toStdString().c_str(), &binPub );

        JS_BIN_set( &binX, binPub.pVal, binPub.nLen/2 );
        JS_BIN_set( &binY, &binPub.pVal[binX.nLen], binPub.nLen/2 );

        ret = JS_PKI_getECDHSecretWithValue( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binX, &binY, &binSecret );

        JS_BIN_reset( &binX );
        JS_BIN_reset( &binY );
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binSecret, &pHex );
        mSecretKeyText->setPlainText(pHex);
        JS_free( pHex );
    }

    repaint();
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binSecret );
}

void KeyAgreeDlg::secretClear()
{
    mSecretKeyText->clear();
    repaint();
}

void KeyAgreeDlg::initialize()
{
    mGCombo->addItems( sGList );
    mECDHParamCombo->addItems( sECCParamList );

    mLengthText->setText( "128" );
    mTabWidget->setCurrentIndex(0);
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
    repaint();
}

void KeyAgreeDlg::genADHPri()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = mLengthText->text().toInt();
    nLen = nLen / 8;

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mAPrivateKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );
    repaint();
}

void KeyAgreeDlg::genBDHPri()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = mLengthText->text().toInt();
    nLen = nLen / 8;

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mBPrivateKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );
    repaint();
}

void KeyAgreeDlg::genADHKey()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );

    JS_BIN_decodeHex( mAPrivateKeyText->text().toStdString().c_str(), &binPri );

    if( binPri.nLen > 0 )
        ret = JS_PKI_genDHPub( &binP, &binG, &binPri, &binPub );
    else
        ret = JS_PKI_genDHKey( &binP, &binG, &binPri, &binPub );

    if( ret == 0 )
    {
        char *pHex = NULL;

        JS_BIN_encodeHex( &binPri, &pHex );

        if( pHex )
        {
            mAPrivateKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

        JS_BIN_encodeHex( &binPub, &pHex );
        if( pHex )
        {
            mAPublicKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    repaint();
}

void KeyAgreeDlg::genBDHKey()
{
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    JS_BIN_decodeHex( mPText->toPlainText().toStdString().c_str(), &binP );
    JS_BIN_decodeHex( mGText->text().toStdString().c_str(), &binG );

    JS_BIN_decodeHex( mBPrivateKeyText->text().toStdString().c_str(), &binPri );

    if( binPri.nLen > 0 )
        ret = JS_PKI_genDHPub( &binP, &binG, &binPri, &binPub );
    else
        ret = JS_PKI_genDHKey( &binP, &binG, &binPri, &binPub );

    if( ret == 0 )
    {
        char *pHex = NULL;

        JS_BIN_encodeHex( &binPri, &pHex );

        if( pHex )
        {
            mBPrivateKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

        JS_BIN_encodeHex( &binPub, &pHex );
        if( pHex )
        {
            mBPublicKeyText->setText( pHex );
            JS_free( pHex );
            pHex = NULL;
        }

    }

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    repaint();
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
    int nNid = JS_PKI_getNidFromSN( strParam.toStdString().c_str() );

    ret = JS_PKI_ECCGenKeyPair( nNid, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    strPub = sKeyVal.pPubX;
    strPub += sKeyVal.pPubY;

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
    int nNid = JS_PKI_getNidFromSN( strParam.toStdString().c_str() );

    ret = JS_PKI_ECCGenKeyPair( nNid, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    strPub = sKeyVal.pPubX;
    strPub += sKeyVal.pPubY;

    mBECDHPriKeyText->setText( sKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetECKeyVal( &sKeyVal );
}

void KeyAgreeDlg::genAECDHPriKey()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = JS_PKI_getECKeyLen( mECDHParamCombo->currentText().toStdString().c_str() );

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mAECDHPriKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );

    repaint();
}

void KeyAgreeDlg::genAECDHPubKey()
{
    BIN binAPri = {0,0};
    BIN binAPubX = {0,0};
    BIN binAPubY = {0,0};
    QString strPub;


    JS_BIN_decodeHex( mAECDHPriKeyText->text().toStdString().c_str(), &binAPri );
    JS_PKI_genECPubKey( mECDHParamCombo->currentText().toStdString().c_str(), &binAPri, &binAPubX, &binAPubY );

    strPub = getHexString( binAPubX.pVal, binAPubX.nLen );
    strPub += getHexString( binAPubY.pVal, binAPubY.nLen );

    mAECDHPubKeyText->setText( strPub );

    JS_BIN_reset( &binAPri );
    JS_BIN_reset( &binAPubX );
    JS_BIN_reset( &binAPubY );

    repaint();
}

void KeyAgreeDlg::findAECDHPriKey()
{
    BIN binECKey = {0,0};
    BIN binOID = {0,0};
    JECKeyVal sECKeyVal;
    char        sTextOID[1024];
    const char  *pSN = NULL;

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    QString strPath = berApplet->getSetPath();
    QString strPub;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    JS_BIN_fileRead( fileName.toStdString().c_str(), &binECKey );
    JS_PKI_getECKeyVal( &binECKey, &sECKeyVal );
    JS_BIN_decodeHex( sECKeyVal.pGroup, &binOID );
    JS_PKI_getStringFromOID( &binOID, sTextOID );
    pSN = JS_PKI_getSNFromOID( sTextOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mAECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mAECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );


    JS_PKI_resetECKeyVal( &sECKeyVal );
    repaint();
}

void KeyAgreeDlg::genBECDHPriKey()
{
    BIN binPri = {0,0};
    char *pHex = NULL;
    int nLen = JS_PKI_getECKeyLen( mECDHParamCombo->currentText().toStdString().c_str() );

    JS_PKI_genRandom( nLen, &binPri );
    JS_BIN_encodeHex( &binPri, &pHex );
    mBECDHPriKeyText->setText( pHex );

    if( pHex ) JS_free( pHex );
    repaint();
}

void KeyAgreeDlg::genBECDHPubKey()
{
    BIN binPri = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    QString strPub;

    JS_BIN_decodeHex( mBECDHPriKeyText->text().toStdString().c_str(), &binPri );
    JS_PKI_genECPubKey( mECDHParamCombo->currentText().toStdString().c_str(), &binPri, &binPubX, &binPubY );

    strPub = getHexString( binPubX.pVal, binPubX.nLen );
    strPub += getHexString( binPubY.pVal, binPubY.nLen );

    mBECDHPubKeyText->setText( strPub );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    repaint();
}

void KeyAgreeDlg::findBECDHPriKey()
{
    BIN binECKey = {0,0};
    BIN binOID = {0,0};
    JECKeyVal sECKeyVal;
    char        sTextOID[1024];
    const char  *pSN = NULL;

    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    QString strPath = berApplet->getSetPath();
    QString strPub;

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.isEmpty() ) return;

    JS_BIN_fileRead( fileName.toStdString().c_str(), &binECKey );
    JS_PKI_getECKeyVal( &binECKey, &sECKeyVal );
    JS_BIN_decodeHex( sECKeyVal.pGroup, &binOID );
    JS_PKI_getStringFromOID( &binOID, sTextOID );
    pSN = JS_PKI_getSNFromOID( sTextOID );

    strPub += sECKeyVal.pPubX;
    strPub += sECKeyVal.pPubY;

    mBECDHPriKeyText->setText( sECKeyVal.pPrivate );
    mBECDHPubKeyText->setText( strPub );
    mECDHParamCombo->setCurrentText( pSN );


    JS_PKI_resetECKeyVal( &sECKeyVal );
    repaint();
}

void KeyAgreeDlg::pChanged()
{
    int nLen = getDataLen( DATA_HEX, mPText->toPlainText() );
    mPLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::APriKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mAPrivateKeyText->text() );
    mAPrivateKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::APubKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mAPublicKeyText->text() );
    mAPublicKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::BPriKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mBPrivateKeyText->text() );
    mBPrivateKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::BPubKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mBPublicKeyText->text() );
    mBPublicKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::AECDHPriKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mAECDHPriKeyText->text() );
    mAECDHPriKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::AECDHPubKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mAECDHPubKeyText->text() );
    mAECDHPubKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::BECDHPriKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mBECDHPriKeyText->text() );
    mBECDHPriKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::BECDHPubKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mBECDHPubKeyText->text() );
    mBECDHPubKeyLenText->setText( QString("%1").arg(nLen));
}

void KeyAgreeDlg::secretKeyChanged()
{
    int nLen = getDataLen( DATA_HEX, mSecretKeyText->toPlainText() );
    mSecretKeyLenText->setText( QString("%1").arg(nLen));
}
