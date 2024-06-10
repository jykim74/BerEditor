#include "key_pair_man_dlg.h"

KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

KeyPairManDlg::~KeyPairManDlg()
{

}
