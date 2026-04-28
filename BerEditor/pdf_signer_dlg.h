#ifndef PDF_SIGNER_DLG_H
#define PDF_SIGNER_DLG_H

#include <QDialog>
#include "ui_pdf_signer_dlg.h"
#include "js_bin.h"

#ifdef PDF_SIGN

namespace Ui {
class PDFSignerDlg;
}

const QString kDSS = "DSS";
const QString kDSS_Certs = "Certs";
const QString kDSS_CRLs = "CRLs";
const QString kDSS_OCSPs = "OCSPs";
const QString kDSS_Cert = "Certificate";
const QString kDSS_CRL = "CRL";
const QString kDSS_OCSP = "OCSP Rsp";
const QString kDocTimeStamp = "DocTimeStamp";

class PDFSignerDlg : public QDialog, public Ui::PDFSignerDlg
{
    Q_OBJECT

public:
    explicit PDFSignerDlg(QWidget *parent = nullptr);
    ~PDFSignerDlg();

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);
    void slotTableMenuRequested( QPoint pos );
    void slotTreeMenuRequested( QPoint pos );

    void copyValue();
    void decodeValue();
    void viewValue();

    void copyTreeValue();
    void decodeTreeValue();
    void viewTreeValue();

    void findSrcPath();
    void findDstPath();
    void clickClearAll();

    void checkUseTSP();
    void clickTSP();

    void checkNameSubjectDN();

    void clickGetInfo();
    void clickMakeSign();
    void clickVerifySign();
    void clickClearInfo();
    void clickEncrypt();
    void clickDecrypt();

    void clickViewCMS();
    void clickExportCMS();

    void clickAddDSS();
    void clickAddDSS_VRI();
    void clickAddDocTSP();
    void clickViewDocTSP();
    void clickVerifyDocTSP();
    void clickViewDocTSP_TST();

    void clickExportByteRange();
    void clickExportDocTSPByteRange();

    void clickDstPathUp();
private:
    void initUI();
    void initialize();
    int getTSP( const BIN *pSrc, BIN *pTSP );
    int getPriKeyCert( BIN *pPriKey, BIN *pCert );
    int getCert( BIN *pCert );

    int appendDSS( const QString strSrcPath,
                  const QString strDstPath,
                  const BIN *pCert );

    int appendDSS_VRI( const QString strSrcPath,
                      const QString strDstPath,
                      const BIN *pCMS,
                      const BIN *pCert );
};

#endif

#endif // PDF_SIGNER_DLG_H
