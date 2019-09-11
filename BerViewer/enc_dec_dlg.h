#ifndef ENC_DEC_DLG_H
#define ENC_DEC_DLG_H

#include <QDialog>

namespace Ui {
class EncDecDlg;
}

class EncDecDlg : public QDialog
{
    Q_OBJECT

public:
    explicit EncDecDlg(QWidget *parent = nullptr);
    ~EncDecDlg();

private:
    Ui::EncDecDlg *ui;
};

#endif // ENC_DEC_DLG_H
