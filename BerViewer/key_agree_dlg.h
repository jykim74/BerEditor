#ifndef KEY_AGREE_DLG_H
#define KEY_AGREE_DLG_H

#include <QDialog>
#include "ui_key_agree_dlg.h"

namespace Ui {
class KeyAgreeDlg;
}

class KeyAgreeDlg : public QDialog, public Ui::KeyAgreeDlg
{
    Q_OBJECT

public:
    explicit KeyAgreeDlg(QWidget *parent = nullptr);
    ~KeyAgreeDlg();

private slots:
    void calcualte();
    void genDHParam();
    void genDHKey();
    void findPriKey();
    void findCert();
    void mechChanged( int index );


private:
    void initialize();
};

#endif // KEY_AGREE_DLG_H
