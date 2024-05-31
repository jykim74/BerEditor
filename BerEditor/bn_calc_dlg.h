#ifndef BN_CALC_DLG_H
#define BN_CALC_DLG_H

#include <QDialog>
#include "ui_bn_calc_dlg.h"
#include "js_bin.h"

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

    void clickACheckPrime();
    void clickBCheckPrime();
    void clickModCheckPrime();

    void changeBaseGroup( int index );

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
    void clickSqrt();

    void clearA();
    void clearB();
    void clearMod();
    void clearRes();
    void clearAll();

    void changeA();
    void changeB();
    void changeMod();
    void changeRes();

    void clickACopy();
    void clickAPaste();
    void clickBCopy();
    void clickBPaste();
    void clickModCopy();
    void clickModPaste();
    void clickResCopy();

    void clickTest();
private:
    void intialize();
    int getInput( BIN *pA, BIN *pB, BIN *pMod );

    const QString getOutput( const BIN *pBin );
    void getBIN( const QString strValue, BIN *pBin );
};

#endif // BN_CALC_DLG_H
