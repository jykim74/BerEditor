#ifndef PDF_SIGNER_DLG_H
#define PDF_SIGNER_DLG_H

#include <QDialog>
#include "ui_pdf_signer_dlg.h"
#include "js_bin.h"

#ifdef PDF_SIGN

namespace Ui {
class PDFSignerDlg;
}

const QString kDSS_Cert = "DSS Cert";
const QString kDSS_CRL = "DSS CRL";
const QString kDSS_OCSP = "DSS OCSP";
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

    void copyValue();
    void decodeValue();
    void viewValue();

    void findSrcPath();
    void findDstPath();
    void clickClearAll();

    void checkUseTSP();
    void clickTSP();

    void checkSign();
    void checkEnc();
    void checkNameSubjectDN();

    void clickGetInfo();
    void clickMakeSign();
    void clickVerifySign();
    void clickClearInfo();
    void clickEncrypt();
    void clickDecrypt();

    void clickViewCMS();
    void clickExportCMS();
    void clickMake();
    void clickVerify();

    void clickAddDSS();
    void clickAddDocTSP();
    void clickVerifyDocTSP();

    void clickExportByteRange();
    void clickExportDocTSPByteRange();

    void clickDstPathUp();
private:
    void initUI();
    void initialize();
    int getTSP( const BIN *pSrc, BIN *pTSP );
    int getPriKeyCert( BIN *pPriKey, BIN *pCert );
    int getCert( BIN *pCert );
};

#endif

#endif // PDF_SIGNER_DLG_H
