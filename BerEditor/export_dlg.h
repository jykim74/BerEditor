#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>
#include "ui_export_dlg.h"
#include "js_bin.h"

namespace Ui {
class ExportDlg;
}

enum {
    DataPriKey = 1,
    DataCert,
    DataCRL,
    DataCSR,
    DataPriKeyCert,
};

enum {
    ExportPubPEM = 1,   // PEM public (*.pem)
    ExportPubDER,       // DER public (*.der)
    ExportPriPEM,       // PEM private (*.pem)
    ExportPriDER,       // DER private (*.der)
    ExportCertPEM,      // PEM certificate (*.crt)
    ExportCertDER,      // DER certificate (*.cer)
    ExportPFX,          // PKCS12 (*.pfx)
    ExportP8InfoPEM,    // PEM PKCS8 Info (*.pk8)
    ExportP8InfoDER,    // DER PKCS8 Info (*.der)
    ExportP8EncPEM,     // PEM PKCS8 Encrypt (*.key)
    ExportP8EncDER,     // DER PKCS8 Encrypt (*.der)
    ExportCSR_PEM,      // PEM CSR (*.csr)
    ExportCSR_DER,      // DER CSR (*.der)
    ExportCRL_PEM,      // PEM CRL (*.crl)
    ExportCRL_DER,      // DER CRL (*.der)
};

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();

    void setName( const QString strName );

    void setPrivateKey( const BIN *pPriKey );
    void setCert( const BIN *pCert );
    void setCRL( const BIN *pCRL );
    void setCSR( const BIN *pCSR );
    void setPriKeyAndCert( const BIN *pPriKey, const BIN *pCert );

private slots:
    void changeFormatType( int index );
    void clickOK();
    void clickFindFilename();

private:
    void initialize();

    int exportPublic();
    int exportPrivate();
    int exportCert();
    int exportCRL();
    int exportCSR();
    int exportPFX();
    int exportP8Enc();
    int exportP8Info();

    BIN pri_key_;
    BIN cert_;
    BIN csr_;
    BIN crl_;

    int data_type_;
    int key_type_;
};

#endif // EXPORT_DLG_H
