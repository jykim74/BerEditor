#ifndef EDIT_TTLV_DLG_H
#define EDIT_TTLV_DLG_H

#include <QDialog>
#include "ui_edit_ttlv_dlg.h"

namespace Ui {
class EditTTLVDlg;
}

class EditTTLVDlg : public QDialog, public Ui::EditTTLVDlg
{
    Q_OBJECT

public:
    explicit EditTTLVDlg(QWidget *parent = nullptr);
    ~EditTTLVDlg();
    QString getData();

private slots:
    void clickModify();
    void clickAdd();
    void changeValue();
    void changeTTLV();

private:
    void initialize();
    void makeHeader();
};

#endif // EDIT_TTLV_DLG_H
