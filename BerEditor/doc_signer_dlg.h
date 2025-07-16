#ifndef DOC_SIGNER_DLG_H
#define DOC_SIGNER_DLG_H

#include <QDialog>
#include "ui_doc_signer_dlg.h"

namespace Ui {
class DocSignerDlg;
}

class DocSignerDlg : public QDialog, public Ui::DocSignerDlg
{
    Q_OBJECT

public:
    explicit DocSignerDlg(QWidget *parent = nullptr);
    ~DocSignerDlg();

private slots:
    void clickClearAll();

    void clickJSON_ComputeSignature();
    void clickJSON_VerifySignature();
    void clickJSON_PayloadClear();
    void clickJSON_JWKClear();
    void clickJSON_PayloadView();
    void clickJSON_JWKView();

private:

};

#endif // DOC_SIGNER_DLG_H
