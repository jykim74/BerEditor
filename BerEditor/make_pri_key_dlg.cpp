#include "make_pri_key_dlg.h"

MakePriKeyDlg::MakePriKeyDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    tabRSA->layout()->setSpacing(5);
    tabRSA->layout()->setMargin(5);
    tabECC->layout()->setSpacing(5);
    tabECC->layout()->setMargin(5);
    tabDSA->layout()->setSpacing(5);
    tabDSA->layout()->setMargin(5);
    tabRaw->layout()->setSpacing(5);
    tabRaw->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakePriKeyDlg::~MakePriKeyDlg()
{

}
