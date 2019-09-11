#ifndef ABOUT_DLG_H
#define ABOUT_DLG_H

#include <QDialog>

namespace Ui {
class AboutDlg;
}

class AboutDlg : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDlg(QWidget *parent = nullptr);
    ~AboutDlg();

private:
    Ui::AboutDlg *ui;
};

#endif // ABOUT_DLG_H
