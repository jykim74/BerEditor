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

private slots:
    void clickBinary();
    void clickDecimal();
    void clickHex();

    void clickAdd();
    void clickSub();
    void clickMultiple();
    void clickDiv();

private:
    void intialize();
};

#endif // BN_CALC_DLG_H
