#include "js_pki.h"
#include "js_error.h"

#include "vid_dlg.h"
#include "common.h"
#include "settings_mgr.h"
#include "ber_applet.h"
#include "mainwindow.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

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
    connect( mRandText, SIGNAL(textChanged(QString)), this, SLOT(changeRand(QString)));
    connect( mHashContentText, SIGNAL(textChanged()), this, SLOT(changeHashContent()));
    connect( mVIDText, SIGNAL(textChanged()), this, SLOT(changeVID()));

    initialize();
}

VIDDlg::~VIDDlg()
{

}

void VIDDlg::initialize()
{
    mRandCombo->addItems( dataTypes );
    mHashCombo->addItems( kHashList );

    mHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
}

void VIDDlg::changeSSN( const QString& text )
{
    QString strSSN = mSSNText->text();
    mSSNLenText->setText( QString("%1").arg( strSSN.length() ));
}

void VIDDlg::changeRand( const QString& text )
{
    QString strRand = mRandText->text();
    int nLen = getDataLen( mRandCombo->currentText(), strRand );
    mRandLenText->setText( QString("%1").arg( nLen ));
}

void VIDDlg::changeVID()
{
    QString strVID = mVIDText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strVID );
    mVIDLenText->setText( QString("%1").arg( nLen ));
}

void VIDDlg::changeHashContent()
{
    QString strHashContent = mHashContentText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strHashContent );
    mHashContentLenText->setText( QString("%1").arg( nLen ));
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
        return;
    }

    if( strRand.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter random value" ), this );
        return;
    }

    if( strVID.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter VID value" ), this );
        return;
    }

    getBINFromString( &binRand, mRandCombo->currentText(), strRand );
    getBINFromString( &binVID, DATA_HEX, strVID );

    ret = JS_PKI_verifyVID( strSSN.toStdString().c_str(), &binRand, &binVID, &binHashContent );

    if( ret == JSR_VERIFY )
    {
        berApplet->messageLog( tr( "VID verification successful"), this );
        mHashContentText->setPlainText( getHexString( &binHashContent ));
    }
    else
    {
        berApplet->warnLog( tr( "VID verification failed: %1" ).arg( ret ), this );
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
        return;
    }

    if( strRand.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter random value" ), this );
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
    berApplet->decodeData( &binData, "" );
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
    berApplet->decodeData( &binData, "" );
    JS_BIN_reset( &binData );
}

void VIDDlg::clickClearHashContent()
{
    mHashContentText->clear();
}
