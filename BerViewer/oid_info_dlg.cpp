#include "oid_info_dlg.h"
#include "ber_define.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "ber_applet.h"

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
}

OIDInfoDlg::~OIDInfoDlg()
{

}

void OIDInfoDlg::initialize()
{
    mInputTypeCombo->addItems( oidTypes );
    mInputText->setFocus();
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
