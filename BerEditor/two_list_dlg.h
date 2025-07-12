#ifndef TWO_LIST_DLG_H
#define TWO_LIST_DLG_H

#include <QDialog>
#include "ui_two_list_dlg.h"

namespace Ui {
class TwoListDlg;
}

class TwoListDlg : public QDialog, public Ui::TwoListDlg
{
    Q_OBJECT

public:
    explicit TwoListDlg(QWidget *parent = nullptr);
    ~TwoListDlg();

    void setNames( const QString strName, const QString strName2 );
    void addNames( const QString strName, const QString strName2 );

    const QStringList getList();

private slots:
    void clickAdd();
    void clickOK();
    void clickClear();

private:
    void initUI();
};

#endif // TWO_LIST_DLG_H
