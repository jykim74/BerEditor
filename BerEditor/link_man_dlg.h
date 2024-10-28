#ifndef LINK_MAN_DLG_H
#define LINK_MAN_DLG_H

#include <QDialog>
#include "ui_link_man_dlg.h"

namespace Ui {
class LinkManDlg;
}

class LinkManDlg : public QDialog, public Ui::LinkManDlg
{
    Q_OBJECT

public:
    explicit LinkManDlg(QWidget *parent = nullptr);
    ~LinkManDlg();

private slots:
    void clickAdd();
    void clickRemove();
    void clickClearAll();
    void clickOK();

private:
    void initialize();
};

#endif // LINK_MAN_DLG_H
