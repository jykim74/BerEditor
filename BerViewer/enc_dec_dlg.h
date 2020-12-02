#ifndef ENC_DEC_DLG_H
#define ENC_DEC_DLG_H

#include <QDialog>
#include "ui_enc_dec_dlg.h"

namespace Ui {
class EncDecDlg;
}

class EncDecDlg : public QDialog, public Ui::EncDecDlg
{
    Q_OBJECT

public:
    explicit EncDecDlg(QWidget *parent = nullptr);
    ~EncDecDlg();

private slots:
    void showEvent(QShowEvent *event );
    void Run();
    void clickUseAE();
    void encDecInit();
    void encDecUpdate();
    void encDecFinal();
    void dataChange();

private:
    void initialize();
    bool isCCM( const QString strAlg );
    void *ctx_;
};

#endif // ENC_DEC_DLG_H
