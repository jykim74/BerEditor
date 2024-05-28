#include "bn_calc_dlg.h"

BNCalcDlg::BNCalcDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    intialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

BNCalcDlg::~BNCalcDlg()
{

}

void BNCalcDlg::intialize()
{
    mDecCheck->setChecked(true);
}
