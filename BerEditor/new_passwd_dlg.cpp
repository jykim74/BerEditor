#include "new_passwd_dlg.h"
#include "common.h"
#include "ber_applet.h"

NewPasswdDlg::NewPasswdDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

NewPasswdDlg::~NewPasswdDlg()
{

}

void NewPasswdDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void NewPasswdDlg::clickOK()
{
    QString strPasswd = mPasswdText->text();
    QString strConfirm = mConfirmText->text();

    if( strPasswd.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a password" ), this );
        return;
    }

    if( strConfirm.length() < 1 )
    {
        berApplet->warningBox( tr("Enter a confirm password" ), this );
        return;
    }

    if( strPasswd != strConfirm )
    {
        berApplet->warningBox( tr( "Password and Confirm are different"), this );
        return;
    }

    QDialog::accept();
}
