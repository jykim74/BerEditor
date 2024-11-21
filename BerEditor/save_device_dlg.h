#ifndef SAVE_DEVICE_DLG_H
#define SAVE_DEVICE_DLG_H

#include <QDialog>
#include "ui_save_device_dlg.h"

namespace Ui {
class SaveDeviceDlg;
}

enum DeviceType {
    DeviceHDD = 0,
    DeviceHSM
};

class SaveDeviceDlg : public QDialog, public Ui::SaveDeviceDlg
{
    Q_OBJECT

public:
    explicit SaveDeviceDlg(QWidget *parent = nullptr);
    ~SaveDeviceDlg();
    int getDevice() { return device_; };

private slots:
    void clickHDD();
    void clickHSM();

private:
    int device_;
};

#endif // SAVE_DEVICE_DLG_H
