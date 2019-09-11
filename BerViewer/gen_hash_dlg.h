#ifndef GEN_HASH_DLG_H
#define GEN_HASH_DLG_H

#include <QDialog>

namespace Ui {
class GenHashDlg;
}

class GenHashDlg : public QDialog
{
    Q_OBJECT

public:
    explicit GenHashDlg(QWidget *parent = nullptr);
    ~GenHashDlg();

private:
    Ui::GenHashDlg *ui;
};

#endif // GEN_HASH_DLG_H
