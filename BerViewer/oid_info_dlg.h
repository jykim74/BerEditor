#ifndef OID_INFO_DLG_H
#define OID_INFO_DLG_H

#include <QDialog>

namespace Ui {
class OIDInfoDlg;
}

class OIDInfoDlg : public QDialog
{
    Q_OBJECT

public:
    explicit OIDInfoDlg(QWidget *parent = nullptr);
    ~OIDInfoDlg();

private:
    Ui::OIDInfoDlg *ui;
};

#endif // OID_INFO_DLG_H
