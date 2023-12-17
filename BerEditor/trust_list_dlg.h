#ifndef TRUST_LIST_DLG_H
#define TRUST_LIST_DLG_H

#include <QDialog>
#include "ui_trust_list_dlg.h"

namespace Ui {
class TrustListDlg;
}

class TrustListDlg : public QDialog, public Ui::TrustListDlg
{
    Q_OBJECT

public:
    explicit TrustListDlg(QWidget *parent = nullptr);
    ~TrustListDlg();

private slots:
    void clickAdd();
    void clickDelete();

private:
    void initialize();
    void loadList();
    void clearList();
};

#endif // TRUST_LIST_DLG_H
