#include "auth_ref_dlg.h"

AuthRefDlg::AuthRefDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

}

AuthRefDlg::~AuthRefDlg()
{

}
