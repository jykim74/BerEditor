#ifndef CERT_INFO_DLG_H
#define CERT_INFO_DLG_H

#include <QDialog>
#include "ui_cert_info_dlg.h"


namespace Ui {
class CertInfoDlg;
}

class CertInfoDlg : public QDialog, public Ui::CertInfoDlg
{
    Q_OBJECT

public:
    explicit CertInfoDlg(QWidget *parent = nullptr);
    ~CertInfoDlg();

    QString getCertPath() { return cert_path_; };
    void setCertPath( const QString strPath );
    QTableWidgetItem* getExtNameItem( const QString strSN );

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );

private:
    QString cert_path_;

    void initialize();
    void initUI();
    void clearTable();
};

#endif // CERT_INFO_DLG_H
