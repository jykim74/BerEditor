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
    void setOKHide( bool bHide = true );

    const QString getPriKeyHex();
    const QString getCertHex();

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void clickViewCert();
    void clickDeleteCert();
    void clickDecodeCert();
    void clickDecodePriKey();
    void clickCheckKeyPair();
    void clickImport();
    void clickExport();
    void clickChangePasswd();

    void clickOK();

    void clickAddTrust();
    void clickRemoveTrust();
    void clickViewTrust();
    void clickDecodeTrust();

private:
    void initUI();
    void initialize();
    const QString getSeletedPath();

    void loadList( const QString strDir );
    void loadEEList();
    void loadTrustCAList();
    void clearCAList();
    void clearEEList();

    int writePriKeyCert( const BIN *pEncPriKey, const BIN *pCert );
    int changePriKey( const BIN *pNewEncPriKey );
    int readPriKeyCert( BIN *pEncPriKey, BIN *pCert );

    BIN pri_key_;
    BIN cert_;
};

#endif // CERT_MAN_DLG_H
