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
    void setManage( bool bMan = true );
//    const QString getData() { return str_data_; };
    const QString getKey();
    const QString getIV();
    void setTitle( const QString strTitle );

    static int getPlainKeyIV( const QString strData, QString& strKey, QString& strIV );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void slotTableMenuRequested( QPoint pos );

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
