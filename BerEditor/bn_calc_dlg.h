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
    void clickAGenPrime();
    void clickBGenPrime();
    void clickModGenPrime();

    void clickAdd();
    void clickSub();
    void clickMultiple();
    void clickDiv();
    void clickExp();
    void clickSqr();

    void clickMod();
    void clickGcd();
    void clickOr();
    void clickAnd();
    void clickXor();
    void clickComp();
    void clickShr();
    void clickShl();
    void clickInv();

    void clearA();
    void clearB();
    void clearMod();
    void clearRes();
    void clearAll();

private:
    void intialize();
};

#endif // BN_CALC_DLG_H
