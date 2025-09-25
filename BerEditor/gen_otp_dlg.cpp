/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDateTime>

#include "gen_otp_dlg.h"
#include "ber_applet.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "common.h"
#include "settings_mgr.h"
#include "key_list_dlg.h"


GenOTPDlg::GenOTPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mSetNowBtn, SIGNAL(clicked()), this, SLOT(setNow()));
    connect( mGenOTPBtn, SIGNAL(clicked()), this, SLOT(clickGenOTP()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDateTime, SIGNAL(dateTimeChanged(QDateTime)), this, SLOT(changeDateTime(QDateTime)));

    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    mGenOTPBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GenOTPDlg::~GenOTPDlg()
{

}

void GenOTPDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

//    QDateTime dateTime = QDateTime::currentDateTime();
//    mDateTime->setDateTime(dateTime);
    mDateTime->setTimeSpec( Qt::LocalTime );

    mHashTypeCombo->addItems(kHashList);
    mHashTypeCombo->setCurrentText( setMgr->defaultHash() );
    mKeyTypeCombo->addItems( kDataTypeList );
    mIntervalSpin->setValue(60);
    mLengthSpin->setValue(6);

    mKeyText->setPlaceholderText( tr( "Select KeyList key" ) );

    setNow();
}


void GenOTPDlg::setNow()
{
    QDateTime dateTime = QDateTime::currentDateTime();
    mDateTime->setDateTime( dateTime );
    changeDateTime( dateTime );
}

void GenOTPDlg::clickGenOTP()
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binT = {0,0};
    char sOTP[128];

    time_t tTime = mDateTime->dateTime().toSecsSinceEpoch();
    int nInterval = mIntervalSpin->value();
    int nLen = mLengthSpin->value();

    memset( sOTP, 0x00, sizeof(sOTP));
    QString strKey = mKeyText->text();
    QString strHash = mHashTypeCombo->currentText();

    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));
        keyList.setManage( false );

        if( keyList.exec() == QDialog::Accepted )
        {
            strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKeyTypeCombo->setCurrentText( "Hex" );
                mKeyText->setText( strKey );
            }
        }

        if( strKey.isEmpty() )
        {
            berApplet->warningBox( tr( "Please enter a key value"), this );
            mKeyText->setFocus();
            return;
        }
    }

    getBINFromString( &binKey, mKeyTypeCombo->currentIndex(), strKey );
    if( binKey.nLen <= 0 )
    {
        berApplet->warnLog( tr( "Invalid key value" ), this );
        mKeyText->setFocus();
        return;
    }


    ret = JS_PKI_genOTP( strHash.toStdString().c_str(), tTime, nInterval, nLen, &binKey, &binT, sOTP );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binT, &pHex );
        mTValueText->setText( pHex );
        mOTPValueText->setText(sOTP);
        if( pHex ) JS_free(pHex);
    }

    if( ret == 0 )
    {
        berApplet->logLine();
        berApplet->log( "-- Generate OTP");
        berApplet->logLine2();
        berApplet->log( QString( "Hash     : %1" ).arg( mHashTypeCombo->currentText() ));
        berApplet->log( QString( "DateTime : %1").arg( mDateTime->dateTime().toString( "yyyy-MM-dd HH:mm:ss")));
        berApplet->log( QString( "Time_t   : %1").arg( tTime ));
        berApplet->log( QString( "Interval : %1 sec" ).arg( nInterval ));
        berApplet->log( QString( "Length   : %1").arg( nLen ));
        berApplet->log( QString( "Key      : %1" ).arg( getHexString( &binKey )));
        berApplet->log( QString( "T        : %1" ).arg( getHexString(&binT)));
        berApplet->log( QString( "OTP      : %1").arg( sOTP ));
        berApplet->logLine();
    }
    else
    {
        berApplet->warnLog( tr( "fail to generate OTP: %1").arg(ret), this );
    }

    JS_BIN_reset(&binKey);
    JS_BIN_reset(&binT);
    update();
}

void GenOTPDlg::keyChanged()
{
    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(strLen));
}

void GenOTPDlg::changeDateTime( QDateTime dateTime )
{
    qint64 tEpoch = dateTime.toSecsSinceEpoch();
    mEpochText->setText(QString("%1").arg(tEpoch));
}

void GenOTPDlg::clickClearDataAll()
{
    mKeyText->clear();
    mTValueText->clear();
    mOTPValueText->clear();
}
