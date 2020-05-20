#include <QDateTime>

#include "gen_otp_dlg.h"
#include "ber_applet.h"
#include "ber_define.h"
#include "js_bin.h"
#include "js_pki.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList hashTypes = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512"
};

GenOTPDlg::GenOTPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mSetNowBtn, SIGNAL(clicked()), this, SLOT(setNow()));
}

GenOTPDlg::~GenOTPDlg()
{

}

void GenOTPDlg::initialize()
{
    QDateTime dateTime = QDateTime::currentDateTime();
    mDateTime->setDateTime(dateTime);

    mHashTypeCombo->addItems(hashTypes);
    mKeyTypeCombo->addItems(dataTypes);
    mIntervalSpin->setValue(60);
    mLengthSpin->setValue(6);
}


void GenOTPDlg::setNow()
{
    QDateTime dateTime = QDateTime::currentDateTime();
    mDateTime->setDateTime( dateTime );
}

void GenOTPDlg::accept()
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binT = {0,0};
    char sOTP[128];

    time_t tTime = mDateTime->dateTime().toTime_t();
    int nInterval = mIntervalSpin->value();
    int nLen = mLengthSpin->value();

    memset( sOTP, 0x00, sizeof(sOTP));
    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert key"), this );
        return;
    }

    if( mKeyTypeCombo->currentIndex() == DATA_STRING )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == DATA_HEX )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == DATA_BASE64 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );

    ret = JS_PKI_genOTP( mHashTypeCombo->currentText().toStdString().c_str(), tTime, nInterval, nLen, &binKey, &binT, sOTP );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binT, &pHex );
        mTValueText->setText( pHex );
        mOTPValueText->setText(sOTP);
        if( pHex ) JS_free(pHex);
    }

    JS_BIN_reset(&binKey);
    JS_BIN_reset(&binT);
}
