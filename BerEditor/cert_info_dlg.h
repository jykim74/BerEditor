#ifndef CERT_INFO_DLG_H
#define CERT_INFO_DLG_H

#include <QDialog>
#include "ui_cert_info_dlg.h"
#include "js_bin.h"


namespace Ui {
class CertInfoDlg;
}

class CertInfoDlg : public QDialog, public Ui::CertInfoDlg
{
    Q_OBJECT

public:
    explicit CertInfoDlg(QWidget *parent = nullptr);
    ~CertInfoDlg();

    int setCertPath( const QString strPath );
    QTableWidgetItem* getExtNameItem( const QString strSN );

    void setCertBIN( const BIN *pCert );

    static const QString getCRL_URIFromExt( const QString strExtCRLDP );
    static const QString getOCSP_URIFromExt( const QString strExtAIA );
    static const QString getCA_URIFromExt( const QString strExtAIA );

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );
    void changeFieldType( int index );
    void clickSave();

    void clickMakeTree();
    void clickGetCA();
    void clickGetCRL();
    void clickDecodeCert();
    void clickPathValidation();
    void clickVerifyCert();
    void clickOCSPCheck();
    void clickCRLCheck();

private:
    BIN cert_bin_;
    int saveAsPEM( const BIN *pData );
    int getCA( BIN *pCA );
    int getCRL( BIN *pCRL );

    void getFields();
    void initUI();
    void clearTable();
};

#endif // CERT_INFO_DLG_H
