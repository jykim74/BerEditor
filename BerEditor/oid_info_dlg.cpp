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

static QStringList oidTypes = {
    "OID",
    "OID Hex",
    "Short Name",
    "Long Name"
};

OIDInfoDlg::OIDInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initialize();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(closeDlg()));
    connect( mInputText, SIGNAL(textChanged(const QString&)), this, SLOT(findOID()));
    connect( mCreateBtn, SIGNAL(clicked()), this, SLOT(createOID()));

    mCloseBtn->setFocus();
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
    char sOID[1024];
    BIN binOID = {0,0};
    char *pHex = NULL;
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

   if( mInputTypeCombo->currentIndex() == 0 )
       sprintf( sOID, "%s", strInput.toStdString().c_str() );
   else if(mInputTypeCombo->currentIndex() == 1 )
   {
       JS_BIN_decodeHex( strInput.toStdString().c_str(), &binOID );
       JS_PKI_getStringFromOID( &binOID, sOID );
       JS_BIN_reset(&binOID);
   }
   else if(mInputTypeCombo->currentIndex() == 2 )
   {
       JS_PKI_getOIDFromSN( strInput.toStdString().c_str(), sOID );
   }
   else if(mInputTypeCombo->currentIndex() == 3 )
   {
       JS_PKI_getOIDFromLN( strInput.toStdString().c_str(), sOID );
   }

   mOIDText->setText( sOID );
   JS_PKI_getOIDFromString( sOID, &binOID );
   JS_BIN_encodeHex( &binOID, &pHex );
   mOIDHexText->setText( pHex );
   mSNText->setText( JS_PKI_getSNFromOID(sOID));
   mLNText->setText(JS_PKI_getLNFromOID(sOID));

   JS_BIN_reset(&binOID);
   if( pHex ) JS_free(pHex);

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
        berApplet->warningBox( tr( "OID config file is not set" ), this );
        return;
    }

    if( strOID.isEmpty() )
    {
        berApplet->warningBox( tr("You have to insert OID value"), this );
        mOIDText->setFocus();
        return;
    }

    if( strSN.isEmpty() )
    {
        berApplet->warningBox( tr("You have to insert short name"), this );
        mSNText->setFocus();
        return;
    }

    if( strLN.length() < 1 ) strLN = strSN;

    if( JS_PKI_getSNFromOID( strOID.toStdString().c_str() ) != NULL )
    {
        berApplet->warningBox( tr( "OID %1 is already created").arg(strOID), this );
        return;
    }

    if( JS_PKI_getNidFromSN( strSN.toStdString().c_str() ) > 0 )
    {
        berApplet->warningBox( tr( "SN %1 is already used").arg( strSN ), this );
        return;
    }

    ret = JS_PKI_createOID( strOID.toStdString().c_str(), strSN.toStdString().c_str(), strLN.toStdString().c_str() );
    if( ret <= 0 )
    {
        berApplet->warningBox( tr( "fail to create OID"), this );
        return;
    }

    berApplet->messageBox( tr("OID : %1 is added successfully").arg( strOID ));

    writeOIDConfig( QString( "\n# oid[%1] is added by config" ).arg(strOID) );
    writeOIDConfig( QString( "\nOID = %1").arg( strOID ) );
    writeOIDConfig( QString( "\nSN = %1").arg(strSN));
    writeOIDConfig( QString( "\nLN = %1").arg(strLN));
}
