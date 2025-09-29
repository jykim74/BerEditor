#ifndef DECODE_TTLV_DLG_H
#define DECODE_TTLV_DLG_H

#include <QDialog>
#include "ui_decode_ttlv_dlg.h"

namespace Ui {
class DecodeTTLVDlg;
}

class DecodeTTLVDlg : public QDialog, public Ui::DecodeTTLVDlg
{
    Q_OBJECT

public:
    explicit DecodeTTLVDlg(QWidget *parent = nullptr);
    ~DecodeTTLVDlg();

private slots:
    void clickDecode();
    void changeData();
    void clearData();
    void findData();


private:
    void initialize();
};

#endif // DECODE_TTLV_DLG_H
