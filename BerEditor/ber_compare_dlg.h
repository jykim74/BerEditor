#ifndef BER_COMPARE_DLG_H
#define BER_COMPARE_DLG_H

#include <QDialog>
#include "ui_ber_compare_dlg.h"
#include "ber_model.h"
#include "js_bin.h"

namespace Ui {
class BERCompareDlg;
}

class BERCompareDlg : public QDialog, public Ui::BERCompareDlg
{
    Q_OBJECT

public:
    explicit BERCompareDlg(QWidget *parent = nullptr);
    ~BERCompareDlg();

private slots:
    void clickFindA();
    void clickFindB();
    void clickClear();
    void clickCompare();

private:
    void initUI();
    void initialize();


    BIN binA;
    BIN binB;
};

#endif // BER_COMPARE_DLG_H
