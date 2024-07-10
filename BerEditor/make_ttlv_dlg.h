#ifndef MAKE_TTLV_DLG_H
#define MAKE_TTLV_DLG_H

#include <QDialog>
#include "ui_make_ttlv_dlg.h"

namespace Ui {
class MakeTTLVDlg;
}

class MakeTTLVDlg : public QDialog, public Ui::MakeTTLVDlg
{
    Q_OBJECT

public:
    explicit MakeTTLVDlg(QWidget *parent = nullptr);
    ~MakeTTLVDlg();

private:

};

#endif // MAKE_TTLV_DLG_H
