#include "cmp_client_dlg.h"

CMPClientDlg::CMPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
#endif

    initialize();
}

CMPClientDlg::~CMPClientDlg()
{

}

void CMPClientDlg::initialize()
{

}
