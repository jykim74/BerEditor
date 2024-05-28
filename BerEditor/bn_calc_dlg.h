#ifndef BN_CALC_DLG_H
#define BN_CALC_DLG_H

#include <QDialog>
#include "ui_bn_calc_dlg.h"

namespace Ui {
class BNCalcDlg;
}

class BNCalcDlg : public QDialog, public Ui::BNCalcDlg
{
    Q_OBJECT

public:
    explicit BNCalcDlg(QWidget *parent = nullptr);
    ~BNCalcDlg();

private:
    void intialize();
};

#endif // BN_CALC_DLG_H
