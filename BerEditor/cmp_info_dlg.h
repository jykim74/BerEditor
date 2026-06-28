#ifndef CMP_INFO_DLG_H
#define CMP_INFO_DLG_H

#include <QDialog>
#include "ui_cmp_info_dlg.h"

namespace Ui {
class CMPInfoDlg;
}

class CMPInfoDlg : public QDialog, public Ui::CMPInfoDlg
{
    Q_OBJECT

public:
    explicit CMPInfoDlg(QWidget *parent = nullptr);
    ~CMPInfoDlg();

private:

};

#endif // CMP_INFO_DLG_H
