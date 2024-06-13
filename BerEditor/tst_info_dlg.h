#ifndef TST_INFO_DLG_H
#define TST_INFO_DLG_H

#include <QDialog>
#include "ui_tst_info_dlg.h"

namespace Ui {
class TSTInfoDlg;
}

class TSTInfoDlg : public QDialog, public Ui::TSTInfoDlg
{
    Q_OBJECT

public:
    explicit TSTInfoDlg(QWidget *parent = nullptr);
    ~TSTInfoDlg();

private:

};

#endif // TST_INFO_DLG_H
