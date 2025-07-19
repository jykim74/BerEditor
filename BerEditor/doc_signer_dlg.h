#ifndef DOC_SIGNER_DLG_H
#define DOC_SIGNER_DLG_H

#include <QDialog>
#include <QXmlStreamReader>
#include "ui_doc_signer_dlg.h"
#include "acme_object.h"

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

    void findSrcPath();
    void findDstPath();

    void clickJSON_ComputeSignature();
    void clickJSON_VerifySignature();
    void clickJSON_PayloadClear();
    void clickJSON_JWSClear();
    void clickJSON_PayloadView();
    void clickJSON_JWSView();

    void changeJSON_Payload();
    void changeJSON_JWS();

    void clickXML_MakeSign();
    void clickXML_MakeSign2();
    void clickXML_Encrypt();
    void clickXML_Encrypt2();
    void clickXML_VerifySign();
    void clickXML_Decrypt();

    void changeXML_Body();
    void changeXML_Sign();

    void clickPDF_MakeSign();
    void clickPDF_VerifySign();

    void clickDoc_MakeSign();
    void clickDoc_VerifySign();

private:
    void initUI();
    void initialize();

    ACMEObject json_obj_;
    QXmlStreamReader xml_;
};

#endif // DOC_SIGNER_DLG_H
