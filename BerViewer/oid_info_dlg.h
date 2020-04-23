#ifndef OID_INFO_DLG_H
#define OID_INFO_DLG_H

#include <QDialog>
#include "ui_oid_info_dlg.h"

namespace Ui {
class OIDInfoDlg;
}

class OIDInfoDlg : public QDialog, public Ui::OIDInfoDlg
{
    Q_OBJECT

public:
    explicit OIDInfoDlg(QWidget *parent = nullptr);
    ~OIDInfoDlg();

private slots:
    virtual void accept();
    void findOID();
    void closeDlg();

private:
    void initialize();

};

#endif // OID_INFO_DLG_H
