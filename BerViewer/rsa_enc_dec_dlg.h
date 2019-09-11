#ifndef RSA_ENC_DEC_DLG_H
#define RSA_ENC_DEC_DLG_H

#include <QDialog>

namespace Ui {
class RSAEncDecDlg;
}

class RSAEncDecDlg : public QDialog
{
    Q_OBJECT

public:
    explicit RSAEncDecDlg(QWidget *parent = nullptr);
    ~RSAEncDecDlg();

private:
    Ui::RSAEncDecDlg *ui;
};

#endif // RSA_ENC_DEC_DLG_H
