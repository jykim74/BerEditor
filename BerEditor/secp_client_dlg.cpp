#include "secp_client_dlg.h"

SECPClientDlg::SECPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);


#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
#endif

    initialize();
}

SECPClientDlg::~SECPClientDlg()
{

}

void SECPClientDlg::initialize()
{

}
