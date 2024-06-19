#include "passwd_dlg.h"
#include "ui_passwd_dlg.h"
#include "common.h"
#include "ber_applet.h"

PasswdDlg::PasswdDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

PasswdDlg::~PasswdDlg()
{

}

void PasswdDlg::clickOK()
{
    QString strPasswd = mPasswdText->text();

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a password" ), this );
        return;
    }

    QDialog::accept();
}
