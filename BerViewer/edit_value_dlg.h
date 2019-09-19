#ifndef EDIT_VALUE_DLG_H
#define EDIT_VALUE_DLG_H

#include <QDialog>
#include "ui_edit_value_dlg.h"

class BerItem;

namespace Ui {
class EditValueDlg;
}

class EditValueDlg : public QDialog, public Ui::EditValueDlg
{
    Q_OBJECT

public:
    explicit EditValueDlg(QWidget *parent = nullptr);
    ~EditValueDlg();

    void setItem( BerItem *pItem );
    virtual void accept();

private:
    BerItem *ber_item_;
};

#endif // EDIT_VALUE_DLG_H
