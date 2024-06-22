#ifndef CERT_MAN_DLG_H
#define CERT_MAN_DLG_H

#include <QDialog>
#include "ui_cert_man_dlg.h"
#include "js_bin.h"

enum {
    ManModeBase = 0,
    ManModeSelBoth = 1,
    ManModeSelCert = 2,
    ManModeSelCA = 3,
    ManModeTrust = 4
};

enum {
    TAB_EE_IDX = 0,
    TAB_CA_IDX = 1,
    TAB_TRUST_IDX = 2,
    TAB_TOOL_IEX = 3
};

namespace Ui {
class CertManDlg;
}

class CertManDlg : public QDialog, public Ui::CertManDlg
{
    Q_OBJECT

public:
    explicit CertManDlg(QWidget *parent = nullptr);
    ~CertManDlg();

    void setMode( int nMode );
    void setTitle( const QString strTitle );

    const QString getPriKeyHex();
    const QString getCertHex();
    const QString getCACertHex();

    int getPriKey( BIN *pPriKey );
    int getCert( BIN *pCert );
    int getCACert( BIN *pCA );


    int writePriKeyCert( const BIN *pEncPriKey, const BIN *pCert );
    const QString getSeletedCAPath();

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void changeTLVerison( int index );

    void clickViewCert();
    void clickDeleteCert();
    void clickDecodeCert();
    void clickDecodePriKey();
    void clickCheckKeyPair();
    void clickImport();
    void clickExport();
    void clickChangePasswd();

    void clickOK();

    void clickAddCA();
    void clickRemoveCA();
    void clickViewCA();
    void clickDecodeCA();

    void clickAddTrust();
    void clickRemoveTrust();
    void clickViewTrust();
    void clickDecodeTrust();

    void decodeTLPriKey();
    void decodeTLCert();
    void decodeTLPFX();
    void clearTLPriKey();
    void clearTLCert();
    void clearTLPFX();
    void findTLPriKey();
    void findTLCert();
    void findTLPFX();

    void clickTLCheckKeyPair();
    void clickTLViewCert();
    void clickTLEncryptPFX();
    void clickTLDecryptPFX();
    void clickTLSavePFX();

private:
    void initUI();
    void initialize();
    const QString getSeletedPath();

    void setGroupHide( bool bHide = true );
    void setOKHide( bool bHide = true );
    void setTrustOnly();

    void loadEEList();
    void loadCAList();
    void loadTrustList();
    void clearCAList();
    void clearTrustList();
    void clearEEList();


    int changePriKey( const BIN *pNewEncPriKey );
    int readPriKeyCert( BIN *pEncPriKey, BIN *pCert );
    int readCert( BIN *pCert );
    int readCACert( BIN *pCert );
    const QString getModeName( int nMode );

    BIN pri_key_;
    BIN cert_;
    BIN ca_cert_;
    int mode_;
};

#endif // CERT_MAN_DLG_H
