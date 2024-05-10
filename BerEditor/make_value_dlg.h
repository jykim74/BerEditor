#ifndef MAKE_VALUE_DLG_H
#define MAKE_VALUE_DLG_H

#include <QDialog>
#include "ui_make_value_dlg.h"

namespace Ui {
class MakeValueDlg;
}

class MakeValueDlg : public QDialog, public Ui::MakeValueDlg
{
    Q_OBJECT

public:
    explicit MakeValueDlg(QWidget *parent = nullptr);
    ~MakeValueDlg();
    const QString getValue() { return value_; };

private slots:
    void clickOK();
    void makeValue();
    void hexChanged();
    void typeChanged();

private:
    void initialize();
    QString value_;
};

#endif // MAKE_VALUE_DLG_H
