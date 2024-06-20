#ifndef CERT_MAN_DLG_H
#define CERT_MAN_DLG_H

#include <QDialog>
#include "ui_cert_man_dlg.h"
#include "js_bin.h"

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

    void clickViewCert();
    void clickDeleteCert();
    void clickDecodeCert();
    void clickDecodePriKey();
    void clickCheckKeyPair();
    void clickImport();
    void clickExport();
    void clickChangePasswd();

    void clickAddTrust();
    void clickRemoveTrust();
    void clickViewTrust();
    void clickDecodeTrust();

private:
    void initUI();
    void initialize();

    void loadList( const QString strDir );
    void loadEEList();
    void loadTrustCAList();
    void clearCAList();
    void clearEEList();

    int saveStorage( const BIN *pEncPriKey, const BIN *pCert );
    int readStorage( BIN *pEncPriKey, BIN *pCert );
};

#endif // CERT_MAN_DLG_H
