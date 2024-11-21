#include "save_device_dlg.h"

SaveDeviceDlg::SaveDeviceDlg(QWidget *parent)
    : QDialog(parent)
{
    device_ = DeviceHDD;
    setupUi(this);

    connect( mHDDBtn, SIGNAL(clicked()), this, SLOT(clickHDD()));
    connect( mHSMBtn, SIGNAL(clicked()), this, SLOT(clickHSM()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    mHDDBtn->setDefault(true);
}

SaveDeviceDlg::~SaveDeviceDlg()
{

}

void SaveDeviceDlg::clickHDD()
{
    device_ = DeviceHDD;
    accept();
}

void SaveDeviceDlg::clickHSM()
{
    device_ = DeviceHSM;
    accept();
}
