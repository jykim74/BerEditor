#ifndef KEY_LIST_DLG_H
#define KEY_LIST_DLG_H

#include <QDialog>
#include "ui_key_list_dlg.h"

namespace Ui {
class KeyListDlg;
}

class KeyListDlg : public QDialog, public Ui::KeyListDlg
{
    Q_OBJECT

public:
    explicit KeyListDlg(QWidget *parent = nullptr);
    ~KeyListDlg();
    void setManage( bool bSel = true );
    const QString getData() { return str_data_; };
    void setTitle( const QString strTitle );

private slots:
    void showEvent(QShowEvent *event);

    void clickKeyAdd();
    void clickKeyDel();
    void clickKeyView();
    void clickOK();
    void changeKeyType();
    void clickGenMAC();
    void clickEncDec();

private:
    void initialize();
    void loadKeyList();

    QString str_data_;
};

#endif // KEY_LIST_DLG_H
