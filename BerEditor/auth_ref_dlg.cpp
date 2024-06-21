#include "auth_ref_dlg.h"
#include "common.h"
#include "ber_applet.h"

AuthRefDlg::AuthRefDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

}

AuthRefDlg::~AuthRefDlg()
{

}

void AuthRefDlg::initialize()
{

}

void AuthRefDlg::clickOK()
{
    QString strAuthCode = mAuthCodeText->text();
    QString strRefNum = mRefNumText->text();

    if( strAuthCode.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a authorization code" ), this );
        return;
    }

    if( strRefNum.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a referrence number" ), this );
        return;
    }

    QDialog::accept();
}
