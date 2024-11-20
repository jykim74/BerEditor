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
    TAB_OTHER_IDX = 1,
    TAB_CA_IDX = 2,
    TAB_CRL_IDX = 3,
    TAB_TRUST_IDX = 4,
    TAB_TOOL_IDX = 5
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
    const QString getSeletedPath();
    const QString getSeletedCertPath();
    const QString getSeletedCAPath();
    const QString getSeletedCRLPath();

    static int readCA( const QString strCertPath, const BIN* pCert, BIN *pCA );
    static int writeNameHash( const QString strPath, const BIN *pCert );
    static int writeCRL( const QString strCRLPath, const BIN *pCRL );

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void keyTypeChanged( int index );
    void otherKeyTypeChanged( int index );
    void CAKeyTypeChanged( int index );
    void RCAKeyTypeChanged( int index );

    void changeTLVerison( int index );

    void clickViewCert();
    void clickDeleteCert();
    void clickDecodeCert();
    void clickDecodePriKey();
    void clickCheckKeyPair();
    void clickImport();
    void clickExport();
    void clickChangePasswd();
    void clickViewPriKey();
    void clickViewPubKey();

    void clickRunSign();
    void clickRunVerify();
    void clickRunPubEnc();
    void clickRunPubDec();

    void clickOK();
    void checkHSM();

    void clickAddCA();
    void clickRemoveCA();
    void clickViewCA();
    void clickDecodeCA();
    void clickViewPubKeyCA();
    void clickExportCA();

    void clickAddOther();
    void clickRemoveOther();
    void clickViewOther();
    void clickDecodeOther();
    void clickViewPubKeyOther();
    void clickExportOther();

    void clickRunVerifyOther();
    void clickRunPubEncOther();

    void clickAddCRL();
    void clickRemoveCRL();
    void clickViewCRL();
    void clickDecodeCRL();
    void clickExportCRL();


    void clickAddTrust();
    void clickRemoveTrust();
    void clickViewTrust();
    void clickDecodeTrust();
    void clickViewPubKeyTrust();
    void clickExportTrust();

    void decodeTLPriKey();
    void decodeTLCert();
    void decodeTLPFX();
    void clearTLPriKey();
    void clearTLCert();
    void clearTLPFX();
    void findTLPriKey();
    void findTLCert();
    void findTLPFX();

    void checkTLEncPriKey();
    void clickTLCheckKeyPair();
    void clickTLViewCert();
    void clickTLEncryptPFX();
    void clickTLDecryptPFX();
    void clickTLSavePFX();
    void clickTLViewPriKey();
    void clickTLViewPubKey();

private:
    void initUI();
    void initialize();


    void setGroupHide( bool bHide = true );
    void setOKHide( bool bHide = true );
    void setTrustOnly();

    void loadEEList();
    void loadHsmEEList();
    void loadOtherList();
    void loadCAList();
    void loadCRLList();
    void loadTrustList();
    void clearCAList();
    void clearCRLList();
    void clearTrustList();
    void clearEEList();
    void clearOtherList();


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
