#ifndef KEY_DERIVE_DLG_H
#define KEY_DERIVE_DLG_H

#include <QDialog>
#include "ui_key_derive_dlg.h"

namespace Ui {
class KeyDeriveDlg;
}

class KeyDeriveDlg : public QDialog, public Ui::KeyDeriveDlg
{
    Q_OBJECT

public:
    explicit KeyDeriveDlg(QWidget *parent = nullptr);
    ~KeyDeriveDlg();

private slots:
    void Run();
    void passwordChanged();
    void saltChanged();
    void keyValueChanged();

private:

};

#endif // KEY_DERIVE_DLG_H
