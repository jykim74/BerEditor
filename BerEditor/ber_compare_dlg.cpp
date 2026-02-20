#include "ber_compare_dlg.h"

BERCompareDlg::BERCompareDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

BERCompareDlg::~BERCompareDlg()
{

}

void BERCompareDlg::initUI()
{

}

void BERCompareDlg::initialize()
{

}
