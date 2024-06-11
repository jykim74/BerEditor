#ifndef MAKE_CSR_DLG_H
#define MAKE_CSR_DLG_H

#include <QDialog>
#include "ui_make_csr_dlg.h"

namespace Ui {
class MakeCSRDlg;
}

class MakeCSRDlg : public QDialog, public Ui::MakeCSRDlg
{
    Q_OBJECT

public:
    explicit MakeCSRDlg(QWidget *parent = nullptr);
    ~MakeCSRDlg();

private:

};

#endif // MAKE_CSR_DLG_H
