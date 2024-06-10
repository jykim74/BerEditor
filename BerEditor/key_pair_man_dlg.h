#ifndef KEY_PAIR_MAN_DLG_H
#define KEY_PAIR_MAN_DLG_H

#include <QDialog>
#include "ui_key_pair_man_dlg.h"

namespace Ui {
class KeyPairManDlg;
}

class KeyPairManDlg : public QDialog, public Ui::KeyPairManDlg
{
    Q_OBJECT

public:
    explicit KeyPairManDlg(QWidget *parent = nullptr);
    ~KeyPairManDlg();

private:

};

#endif // KEY_PAIR_MAN_DLG_H
