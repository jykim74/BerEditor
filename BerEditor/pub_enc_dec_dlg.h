#ifndef RSA_ENC_DEC_DLG_H
#define RSA_ENC_DEC_DLG_H

#include <QDialog>
#include "ui_pub_enc_dec_dlg.h"

namespace Ui {
class PubEncDecDlg;
}

class PubEncDecDlg : public QDialog, public Ui::PubEncDecDlg
{
    Q_OBJECT

public:
    explicit PubEncDecDlg(QWidget *parent = nullptr);
    ~PubEncDecDlg();

private slots:
    void Run();
    void clickPubKeyEncrypt();
    void clickCheckKeyPair();
    void findCert();
    void findPrivateKey();
    void changeValue();

    void inputChanged();
    void outputChanged();
    void algChanged();

private:
    void initialize();

};

#endif // RSA_ENC_DEC_DLG_H
