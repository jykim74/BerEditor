#ifndef CAVP_DLG_H
#define CAVP_DLG_H

#include <QDialog>
#include "ui_cavp_dlg.h"

namespace Ui {
class CAVPDlg;
}

class CAVPDlg : public QDialog, public Ui::CAVPDlg
{
    Q_OBJECT

public:
    explicit CAVPDlg(QWidget *parent = nullptr);
    ~CAVPDlg();

private slots:
    void clickSymRun();
    void clickHashRun();
    void clickHMACRun();
    void clickECCRun();
    void clickRSARun();
    void clickDRBGRun();
    void clickPBKDFRun();

    void clickSymFind();
    void clickHashFind();
    void clickHMACFind();
    void clickECCFind();
    void clickRSAFind();
    void clickDRBGFind();
    void clickPBKDFFind();

private:
    void initialize();
    QString getRspFile(const QString &reqFileName );
};

#endif // CAVP_DLG_H
