#include "js_pki.h"
#include "js_error.h"

#include "vid_dlg.h"
#include "common.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "mainwindow.h"


VIDDlg::VIDDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mMakeVIDBtn, SIGNAL(clicked()), this, SLOT(clickMakeVID()));
    connect( mVerifyVIDBtn, SIGNAL(clicked()), this, SLOT(clickVerifyVID()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
    connect( mDecodeVIDBtn, SIGNAL(clicked()), this, SLOT(clickDecodeVID()));
    connect( mDecodeHashContentBtn, SIGNAL(clicked()), this, SLOT(clickDecodeHashContent()));
    connect( mClearHashContentBtn, SIGNAL(clicked()), this, SLOT(clickClearHashContent()));

    connect( mSSNText, SIGNAL(textChanged(QString)), this, SLOT(changeSSN(QString)));
    connect( mRandCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeRand()));
    connect( mRandText, SIGNAL(textChanged(QString)), this, SLOT(changeRand()));
    connect( mHashContentText, SIGNAL(textChanged()), this, SLOT(changeHashContent()));
    connect( mVIDText, SIGNAL(textChanged()), this, SLOT(changeVID()));
    connect( mClearVIDBtn, SIGNAL(clicked()), this, SLOT(clickClearVID()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDecodeVIDBtn->setFixedWidth(34);
    mDecodeHashContentBtn->setFixedWidth(34);
    mClearVIDBtn->setFixedWidth(34);
    mClearHashContentBtn->setFixedWidth(34);
#endif

    initialize();
    mMakeVIDBtn->setDefault(true);

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

VIDDlg::~VIDDlg()
{

}

void VIDDlg::initialize()
{
    mRandCombo->addItems( kDataTypeList );
    mHashCombo->addItems( kHashList );

    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mSSNText->setPlaceholderText( tr( "Enter a identity value") );
    mRandText->setPlaceholderText( tr( "Enter a random value" ) );
    mVIDText->setPlaceholderText( tr( "Hex value" ));
    mHashContentText->setPlaceholderText( tr( "Hex value" ));
}

void VIDDlg::changeSSN( const QString& text )
{
    QString strLen = getDataLenString( DATA_STRING, text );
    mSSNLenText->setText( QString("%1").arg( strLen ));
}

void VIDDlg::changeRand()
{
    QString strRand = mRandText->text();
    QString strLen = getDataLenString( mRandCombo->currentText(), strRand );
    mRandLenText->setText( QString("%1").arg( strLen ));
}

void VIDDlg::changeVID()
{
    QString strVID = mVIDText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strVID );
    mVIDLenText->setText( QString("%1").arg( strLen ));
}

void VIDDlg::changeHashContent()
{
    QString strHashContent = mHashContentText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strHashContent );
    mHashContentLenText->setText( QString("%1").arg( strLen ));
}

void VIDDlg::clickVerifyVID()
{
    int ret = 0;
    BIN binRand = {0,0};
    BIN binVID = {0,0};
    BIN binHashContent = {0,0};

    QString strSSN = mSSNText->text();
    QString strRand = mRandText->text();
    QString strVID = mVIDText->toPlainText();

    if( strSSN.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter SSN" ), this );
        mSSNText->setFocus();
        return;
    }

    if( strRand.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter random value" ), this );
        mRandText->setFocus();
        return;
    }

    if( strVID.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter VID value" ), this );
        mVIDText->setFocus();
        return;
    }

    getBINFromString( &binRand, mRandCombo->currentText(), strRand );
    getBINFromString( &binVID, DATA_HEX, strVID );



    ret = JS_PKI_verifyVID( strSSN.toStdString().c_str(), &binRand, &binVID, &binHashContent );

    if( ret == JSR_VERIFY )
    {
        mHashContentText->setPlainText( getHexString( &binHashContent ));

        berApplet->messageLog( tr( "VID verification successful"), this );

        berApplet->logLine();
        berApplet->log( "-- Verification VID Information" );
        berApplet->logLine2();
        berApplet->log( QString( "SSN         : %1" ).arg( strSSN ));
        berApplet->log( QString( "Random      : %1" ).arg( getHexString( &binRand )));
        berApplet->log( QString( "HashContent : %1").arg( getHexString( &binHashContent )));
        berApplet->log( QString( "VID         : %1" ).arg( getHexString( &binVID )));
        berApplet->logLine();
    }
    else
    {
        berApplet->warnLog( tr( "VID verification failed: %1" ).arg( JERR(ret) ), this );
    }

    JS_BIN_reset( &binRand );
    JS_BIN_reset( &binVID );
    JS_BIN_reset( &binHashContent );
}

void VIDDlg::clickMakeVID()
{
    int ret = 0;

    BIN binRand = {0,0};
    BIN binVID = {0,0};
    BIN binHashContent = {0,0};

    QString strSSN = mSSNText->text();
    QString strRand = mRandText->text();

    if( strSSN.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter SSN" ), this );
        mSSNText->setFocus();
        return;
    }

    if( strRand.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter random value" ), this );
        mRandText->setFocus();
        return;
    }

    getBINFromString( &binRand, mRandCombo->currentText(), strRand );

    ret = JS_PKI_makeVID( mHashCombo->currentText().toStdString().c_str(),
                         strSSN.toStdString().c_str(),
                         &binRand,
                         &binHashContent,
                         &binVID );

    if( ret == 0 )
    {
        mVIDText->setPlainText( getHexString( &binVID ));
        mHashContentText->setPlainText( getHexString( &binHashContent ));

        berApplet->messageLog( tr( "VID creation successful" ), this );

        berApplet->logLine();
        berApplet->log( "-- Generate VID Information" );
        berApplet->logLine2();
        berApplet->log( QString( "SSN         : %1" ).arg( strSSN ));
        berApplet->log( QString( "Random      : %1" ).arg( getHexString( &binRand )));
        berApplet->log( QString( "Hash        : %1" ).arg( mHashCombo->currentText() ));
        berApplet->log( QString( "HashContent : %1").arg( getHexString( &binHashContent )));
        berApplet->log( QString( "VID         : %1" ).arg( getHexString( &binVID )));
        berApplet->logLine();
    }
    else
    {
        berApplet->warnLog( tr( "failed to make VID: %1").arg( ret ), this );
    }

    JS_BIN_reset( &binRand );
    JS_BIN_reset( &binVID );
    JS_BIN_reset( &binHashContent );
}

void VIDDlg::clickClearAll()
{
    mSSNText->clear();
    mRandText->clear();
    mVIDText->clear();
    mHashContentText->clear();
}

void VIDDlg::clickDecodeVID()
{
    BIN binData = {0,0};
    QString strVID = mVIDText->toPlainText();

    if( strVID.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no VID value" ), this );
        return;
    }

    JS_BIN_decodeHex( strVID.toStdString().c_str(), &binData );
    berApplet->decodeData( &binData, "VID" );
    JS_BIN_reset( &binData );
}

void VIDDlg::clickDecodeHashContent()
{
    BIN binData = {0,0};
    QString strHashContent = mHashContentText->toPlainText();
    if( strHashContent.length() < 1 )
    {
        berApplet->warningBox( tr( "There is no HashContent value" ), this );
        return;
    }

    JS_BIN_decodeHex( strHashContent.toStdString().c_str(), &binData );
    berApplet->decodeData( &binData, "Hash Content" );
    JS_BIN_reset( &binData );
}

void VIDDlg::clickClearVID()
{
    mVIDText->clear();
}

void VIDDlg::clickClearHashContent()
{
    mHashContentText->clear();
}
