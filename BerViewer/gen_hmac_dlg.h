#ifndef GEN_HMAC_DLG_H
#define GEN_HMAC_DLG_H

#include <QDialog>
#include "ui_gen_hmac_dlg.h"

namespace Ui {
class GenHmacDlg;
}

class GenHmacDlg : public QDialog, public Ui::GenHmacDlg
{
    Q_OBJECT

public:
    explicit GenHmacDlg(QWidget *parent = nullptr);
    ~GenHmacDlg();

private slots:
        void hmac();
        void hmacInit();
        void hmacUpdate();
        void hmacFinal();

        void inputClear();
        void outputClear();

private:
        void *hctx_;
};

#endif // GEN_HMAC_DLG_H
