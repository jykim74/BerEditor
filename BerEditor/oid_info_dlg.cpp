/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDir>
#include <QTextStream>

#include "oid_info_dlg.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "ber_applet.h"
#include "js_pki_tools.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

static QStringList oidTypes = {
    "OID",
    "OIDValueHex",
    "OIDHex",
    "ShortName",
    "LongName"
};

OIDInfoDlg::OIDInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(closeDlg()));
    connect( mInputText, SIGNAL(textChanged(const QString&)), this, SLOT(findOID()));
    connect( mCreateBtn, SIGNAL(clicked()), this, SLOT(createOID()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));

    mInputText->setFocus();
    mCreateBtn->hide();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

OIDInfoDlg::~OIDInfoDlg()
{

}

void OIDInfoDlg::initialize()
{
    mInputTypeCombo->addItems( oidTypes );
    mInputText->setFocus();
}

int OIDInfoDlg::writeOIDConfig( const QString& strMsg )
{
    QDir dir;
    QString strOIDPath = berApplet->settingsMgr()->OIDConfigPath();

    if( strOIDPath.length() < 1 ) return -1;

    if( dir.exists( strOIDPath ) == 0 )
    {
        bool bval = dir.mkdir( strOIDPath );
        if( bval == NULL ) return -2;
    }


    QFile file( strOIDPath );
    file.open( QFile::WriteOnly | QFile::Append | QFile::Text );
    QTextStream cfgFile( &file );

    cfgFile << strMsg;
    file.close();

    return 0;
}

void OIDInfoDlg::closeDlg()
{
    close();
}

void OIDInfoDlg::findOID()
{
     int nNid = -1;
     char sOID[1024];
     BIN binInput = {0,0};
     BIN binOIDVal = {0,0};
     BIN binOID = {0,0};

     memset( sOID, 0x00, sizeof(sOID) );
     QString strInput = mInputText->text();

     if( strInput.isEmpty() )
     {
//        berApplet->warningBox(tr( "You have to insert OID data" ), this );
         mOIDText->clear();
         mOIDHexText->clear();
         mSNText->clear();
         mLNText->clear();

         return;
     }

    if( mInputTypeCombo->currentText() == "OID" )
    {
        sprintf( sOID, "%s", strInput.toStdString().c_str() );
    }
    else if(mInputTypeCombo->currentText() == "OIDValueHex" )
    {
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
        JS_PKI_getStringFromOIDValue( &binInput, sOID );
    }
    else if( mInputTypeCombo->currentText() == "OIDHex" )
    {
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binInput );
        JS_PKI_getStringFromOID( &binInput, sOID );
    }
    else if(mInputTypeCombo->currentText() == "ShortName" )
    {
        JS_PKI_getOIDFromSN( strInput.toStdString().c_str(), sOID );
    }
    else if(mInputTypeCombo->currentText() == "LongName" )
    {
       JS_PKI_getOIDFromLN( strInput.toStdString().c_str(), sOID );
    }

    mOIDText->setText( sOID );
    JS_PKI_getOIDValueFromString( sOID, &binOIDVal );
    JS_PKI_getOIDFromString( sOID, &binOID );
    nNid = JS_PKI_getNidFromOID( &binOID );
    mOIDValHexText->setText( getHexString( &binOIDVal ) );
    mOIDHexText->setText( getHexString( &binOID ));
    mSNText->setText( JS_PKI_getSNFromOID(sOID));
    mLNText->setText(JS_PKI_getLNFromOID(sOID));
    mNidText->setText( QString( "%1" ).arg( nNid ));


    JS_BIN_reset( &binOIDVal );
    JS_BIN_reset(&binOID);
    JS_BIN_reset( &binInput );

    repaint();
}

void OIDInfoDlg::accept()
{
    QDialog::accept();
}

void OIDInfoDlg::createOID()
{
    int ret = 0;

    QString strOID = mOIDText->text();
    QString strSN = mSNText->text();
    QString strLN = mLNText->text();

    QString strOIDPath = berApplet->settingsMgr()->OIDConfigPath();
    if( strOIDPath.length() < 1 )
    {
        berApplet->warningBox( tr( "OID config file not set" ), this );
        return;
    }

    if( strOID.isEmpty() )
    {
        berApplet->warningBox( tr("Enter a OID value"), this );
        mOIDText->setFocus();
        return;
    }

    if( strSN.isEmpty() )
    {
        berApplet->warningBox( tr("Enter a short name"), this );
        mSNText->setFocus();
        return;
    }

    if( strLN.length() < 1 ) strLN = strSN;

    if( JS_PKI_getSNFromOID( strOID.toStdString().c_str() ) != NULL )
    {
        berApplet->warningBox( tr( "OID %1 has already been created").arg(strOID), this );
        return;
    }

    if( JS_PKI_getNidFromSN( strSN.toStdString().c_str() ) > 0 )
    {
        berApplet->warningBox( tr( "SN %1 has already been used").arg( strSN ), this );
        return;
    }

    ret = JS_PKI_createOID( strOID.toStdString().c_str(), strSN.toStdString().c_str(), strLN.toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "failed to create OID"), this );
        return;
    }

    berApplet->messageBox( tr("OID(%1) has beed added successfully").arg( strOID ), this);

    writeOIDConfig( QString( "\n# oid[%1] is added by config" ).arg(strOID) );
    writeOIDConfig( QString( "\nOID = %1").arg( strOID ) );
    writeOIDConfig( QString( "\nSN = %1").arg(strSN));
    writeOIDConfig( QString( "\nLN = %1").arg(strLN));
}

void OIDInfoDlg::clickOutputClear()
{
    mOIDText->clear();
    mOIDValHexText->clear();
    mOIDHexText->clear();
    mSNText->clear();
    mLNText->clear();
    mNidText->clear();
}
