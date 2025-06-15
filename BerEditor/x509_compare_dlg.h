#ifndef X509_COMPARE_DLG_H
#define X509_COMPARE_DLG_H

#include <QDialog>
#include "ui_x509_compare_dlg.h"

namespace Ui {
class X509CompareDlg;
}

class X509CompareDlg : public QDialog, public Ui::X509CompareDlg
{
    Q_OBJECT

public:
    explicit X509CompareDlg(QWidget *parent = nullptr);
    ~X509CompareDlg();

private slots:
    void clickAFind();
    void clickBFind();
    void clickClear();
    void clickCompare();

private:
    void initUI();
    void initialize();
};

#endif // X509_COMPARE_DLG_H
