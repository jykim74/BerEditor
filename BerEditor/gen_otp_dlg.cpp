#include <QDateTime>

#include "gen_otp_dlg.h"
#include "ber_applet.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "common.h"

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
    "sha512",
    "SM3"
};

GenOTPDlg::GenOTPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mSetNowBtn, SIGNAL(clicked()), this, SLOT(setNow()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));

    mCloseBtn->setFocus();
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

void GenOTPDlg::Run()
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

    berApplet->log( QString( "Hash     : %1" ).arg( mHashTypeCombo->currentText() ));
    berApplet->log( QString( "DateTime : %1").arg( mDateTime->dateTime().toString( "yyyy-MM-dd HH:mm:00")));
    berApplet->log( QString( "Interval : %1 Len : %2" ).arg( nInterval ).arg(nLen));
    berApplet->log( QString( "Key      : %1" ).arg( getHexString( &binKey )));
    berApplet->log( QString( "T        : %1" ).arg( getHexString(&binT)));
    berApplet->log( QString( "OTP      : %1").arg( sOTP ));

    JS_BIN_reset(&binKey);
    JS_BIN_reset(&binT);
    repaint();
}

void GenOTPDlg::keyChanged()
{
    int nLen = getDataLen( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(nLen));
}
