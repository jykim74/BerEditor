#ifndef SAVE_DEVICE_DLG_H
#define SAVE_DEVICE_DLG_H

#include <QDialog>
#include "ui_save_device_dlg.h"

namespace Ui {
class SaveDeviceDlg;
}

class SaveDeviceDlg : public QDialog, public Ui::SaveDeviceDlg
{
    Q_OBJECT

public:
    explicit SaveDeviceDlg(QWidget *parent = nullptr);
    ~SaveDeviceDlg();

private:

};

#endif // SAVE_DEVICE_DLG_H
