#ifndef BER_COMPARE_DLG_H
#define BER_COMPARE_DLG_H

#include <QDialog>
#include "ui_ber_compare_dlg.h"

namespace Ui {
class BERCompareDlg;
}

class BERCompareDlg : public QDialog, public Ui::BERCompareDlg
{
    Q_OBJECT

public:
    explicit BERCompareDlg(QWidget *parent = nullptr);
    ~BERCompareDlg();

private:
    void initUI();
    void initialize();
};

#endif // BER_COMPARE_DLG_H
