#ifndef NAME_DLG_H
#define NAME_DLG_H

#include <QDialog>
#include "ui_name_dlg.h"

namespace Ui {
class NameDlg;
}

class NameDlg : public QDialog, public Ui::NameDlg
{
    Q_OBJECT

public:
    explicit NameDlg(QWidget *parent = nullptr);
    ~NameDlg();

    void setHeadLabel( const QString strHead );
    void setName( const QString strName );

private slots:
    void clickOK();

private:

};

#endif // NAME_DLG_H
