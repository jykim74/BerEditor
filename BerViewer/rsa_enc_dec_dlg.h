#ifndef RSA_ENC_DEC_DLG_H
#define RSA_ENC_DEC_DLG_H

#include <QDialog>
#include "ui_rsa_enc_dec_dlg.h"

namespace Ui {
class RSAEncDecDlg;
}

class RSAEncDecDlg : public QDialog, public Ui::RSAEncDecDlg
{
    Q_OBJECT

public:
    explicit RSAEncDecDlg(QWidget *parent = nullptr);
    ~RSAEncDecDlg();

private:

};

#endif // RSA_ENC_DEC_DLG_H
