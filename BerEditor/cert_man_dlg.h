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
    ManModeSelCRL = 4,
    ManModeTrust = 5
};

enum {
    TAB_EE_IDX = 0,
    TAB_CA_IDX = 1,
    TAB_CRL_IDX = 2,
    TAB_TRUST_IDX = 3,
    TAB_TOOL_IEX = 4
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
    const QString getCRLHex();

    int getPriKey( BIN *pPriKey );
    int getCert( BIN *pCert );
    int getCACert( BIN *pCA );
    int getCRL( BIN *pCRL );


    int writePriKeyCert( const BIN *pEncPriKey, const BIN *pCert );
    const QString getSeletedCAPath();
    const QString getSeletedCRLPath();

    static int readCA( const QString strCertPath, const BIN* pCert, BIN *pCA );
    static int writeCA( const QString strCAPath, const BIN *pCACert );
    static int writeCRL( const QString strCRLPath, const BIN *pCRL );

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

    void clickAddCRL();
    void clickRemoveCRL();
    void clickViewCRL();
    void clickDecodeCRL();

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
    void loadCRLList();
    void loadTrustList();
    void clearCAList();
    void clearCRLList();
    void clearTrustList();
    void clearEEList();


    int changePriKey( const BIN *pNewEncPriKey );
    int readPriKeyCert( BIN *pEncPriKey, BIN *pCert );
    int readCert( BIN *pCert );
    int readCACert( BIN *pCert );
    int readCRL( BIN *pCRL );
    const QString getModeName( int nMode );

    BIN pri_key_;
    BIN cert_;
    BIN ca_cert_;
    BIN crl_;
    int mode_;
};

#endif // CERT_MAN_DLG_H
