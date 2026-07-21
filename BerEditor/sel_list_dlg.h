#ifndef SEL_LIST_DLG_H
#define SEL_LIST_DLG_H

#include <QDialog>
#include "ui_sel_list_dlg.h"

namespace Ui {
class SelListDlg;
}

class SelListDlg : public QDialog, public Ui::SelListDlg
{
    Q_OBJECT

public:
    explicit SelListDlg(QWidget *parent = nullptr);
    ~SelListDlg();
    void setHeadLabel( const QString strLabel );
    void addList( const QString strType, const QString strURL );
    const QString getURL();

private slots:
    void clickOK();

private:
    void initUI();
    void initialize();

    QString type_;
    QString url_;
};

#endif // SEL_LIST_DLG_H
