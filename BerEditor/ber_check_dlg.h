#ifndef BER_CHECK_DLG_H
#define BER_CHECK_DLG_H

#include <QDialog>
#include "ui_ber_check_dlg.h"

namespace Ui {
class BERCheckDlg;
}

class BERCheckDlg : public QDialog, public Ui::BERCheckDlg
{
    Q_OBJECT

public:
    explicit BERCheckDlg(QWidget *parent = nullptr);
    ~BERCheckDlg();

private slots:
    void clickClear();
    void clickFileFind();
    void clickCheckFormat();
    void clickCheckType();

private:
    void initUI();
    void initialize();
};

#endif // BER_CHECK_DLG_H
