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
    DataPubKey,
    DataCert,
    DataCRL,
    DataCSR,
    DataPriKeyCert,
    DataDHParam,
    DataPKCS7,
    DataJSON,
    DataXML,
    DataBIN
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
    ExportDH_PEM,       // PEM DH Param (*.pem)
    ExportDH_DER,       // DER DH Param (*.der)
    ExportPKCS7_PEM,    // PEM PKCS7 (*.p7b)
    ExportPKCS7_DER,    // DER PKCS7 (*.der)
    ExportJSON,         // JSON (*.json)
    ExportXML,          // XML (*.xml)
    ExportBIN,          // Binary (*.bin)
};

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();

    void setName( const QString strName );

    void setPrivateKey( const BIN *pPriKey );
    void setPublicKey( const BIN *pPubKey );
    void setCert( const BIN *pCert );
    void setCRL( const BIN *pCRL );
    void setCSR( const BIN *pCSR );
    void setPriKeyAndCert( const BIN *pPriKey, const BIN *pCert );
    void setDHParam( const BIN *pParam );
    void setPKCS7( const BIN *pPKCS7 );
    void setJSON( const BIN *pJSON );
    void setXML( const BIN *pXML );
    void setBIN( const BIN *pBIN );

private slots:
    void changeFormatType( int index );
    void clickOK();
    void clickFindFilename();
    void clickView();

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
    int exportDHParam();
    int exportPKCS7();
    int exportJSON();
    int exportXML();
    int exportBIN();

    BIN data_;
    BIN data2_;

    int data_type_;
    int key_type_;
};

#endif // EXPORT_DLG_H
