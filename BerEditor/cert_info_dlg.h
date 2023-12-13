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

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );
    void changeFieldType( int index );
    void clickSave();

    void clickOCSPCheck();
    void clickCRLCheck();
private:
    BIN cert_bin_;

    void getFields();
    void initUI();
    void clearTable();
};

#endif // CERT_INFO_DLG_H
