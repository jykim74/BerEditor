#include "make_csr_dlg.h"

MakeCSRDlg::MakeCSRDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
}

MakeCSRDlg::~MakeCSRDlg()
{

}
