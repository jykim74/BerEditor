#ifndef CERT_ID_DLG_H
#define CERT_ID_DLG_H

#include <QDialog>
#include "ui_cert_id_dlg.h"
#include "js_bin.h"

namespace Ui {
class CertIDDlg;
}

class CertIDDlg : public QDialog, public Ui::CertIDDlg
{
    Q_OBJECT

public:
    explicit CertIDDlg(QWidget *parent = nullptr);
    ~CertIDDlg();
    void setResponse( const BIN *pResp );

private:
    void initUI();
    void initialize();

    BIN resp_;
};

#endif // CERT_ID_DLG_H
