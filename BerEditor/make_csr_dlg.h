#ifndef MAKE_CSR_DLG_H
#define MAKE_CSR_DLG_H

#include <QDialog>
#include "ui_make_csr_dlg.h"
#include "js_bin.h"

namespace Ui {
class MakeCSRDlg;
}

class MakeCSRDlg : public QDialog, public Ui::MakeCSRDlg
{
    Q_OBJECT

public:
    explicit MakeCSRDlg(QWidget *parent = nullptr);
    ~MakeCSRDlg();

    const QString getDN();
    void setPriKey( const BIN *pPri );
    const QString getCSRHex();

    void setInfo( const QString strInfo );
    void setSAN( const QStringList listSAN );

private slots:
    void clickOK();
    void clickClear();
    void changeDN();
    void clickSANList();

private:
    void initialize();

    BIN csr_;
    BIN pri_key_;
    QStringList san_list_;
};

#endif // MAKE_CSR_DLG_H
