#ifndef CERT_MAN_DLG_H
#define CERT_MAN_DLG_H

#include <QDialog>
#include "ui_cert_man_dlg.h"

namespace Ui {
class CertManDlg;
}

class CertManDlg : public QDialog, public Ui::CertManDlg
{
    Q_OBJECT

public:
    explicit CertManDlg(QWidget *parent = nullptr);
    ~CertManDlg();

    void setGroupHide( bool bHide = true );

private slots:
    void showEvent(QShowEvent *event);

private:
    void initUI();
    void initialize();

    void loadList( const QString strDir );
    void loadEEList();
    void loadTrustCAList();
    void clearCAList();
    void clearEEList();
};

#endif // CERT_MAN_DLG_H
