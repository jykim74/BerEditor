#ifndef MAKE_CSR_DLG_H
#define MAKE_CSR_DLG_H

#include <QDialog>
#include "ui_make_csr_dlg.h"
#include "js_bin.h"

namespace Ui {
class MakeCSRDlg;
}

class MakeCSRDlg : public QDialog, public Ui::MakeCSRDlg
{
    Q_OBJECT

public:
    explicit MakeCSRDlg(QWidget *parent = nullptr);
    ~MakeCSRDlg();

    const QString getDN();
    void setPriKey( const BIN *pPri );
    const QString getCSRHex();

private slots:
    void clickOK();
    void clickClear();

private:
    void initialize();

    BIN csr_;
    BIN pri_key_;
};

#endif // MAKE_CSR_DLG_H
