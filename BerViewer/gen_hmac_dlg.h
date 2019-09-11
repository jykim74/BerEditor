#ifndef GEN_HMAC_DLG_H
#define GEN_HMAC_DLG_H

#include <QDialog>

namespace Ui {
class GenHmacDlg;
}

class GenHmacDlg : public QDialog
{
    Q_OBJECT

public:
    explicit GenHmacDlg(QWidget *parent = nullptr);
    ~GenHmacDlg();

private:
    Ui::GenHmacDlg *ui;
};

#endif // GEN_HMAC_DLG_H
