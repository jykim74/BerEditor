#ifndef ONE_LIST_DLG_H
#define ONE_LIST_DLG_H

#include <QDialog>
#include "ui_one_list_dlg.h"

namespace Ui {
class OneListDlg;
}

class OneListDlg : public QDialog, public Ui::OneListDlg
{
    Q_OBJECT

public:
    explicit OneListDlg(QWidget *parent = nullptr);
    ~OneListDlg();

    void setName( const QString strName );
    void addName( const QString strName );
    const QStringList getList();

private slots:
    void clickOK();
    void clickAdd();
    void clickClear();

private:
    void initUI();
};

#endif // ONE_LIST_DLG_H
