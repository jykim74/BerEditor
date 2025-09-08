#ifndef DOC_SIGNER_DLG_H
#define DOC_SIGNER_DLG_H

#include <QDialog>
#include <QXmlStreamReader>
#include "ui_doc_signer_dlg.h"
#include "acme_object.h"

#include "js_bin.h"

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
    void changeSignerTab();

    void checkSrcFile();
    void checkDstFile();

    void findSrcPath();
    void findDstPath();

    void checkUseTSP();
    void clickTSP();

    void changeCMSData();

    void clickCMSClear();
    void clickCMSOutputUp();
    void clickCMSView();

    void clickCMSOutputClear();
    void clickCMSOutputDecode();

    void clickCMSMakeSign();
    void clickCMSVerifySign();

    void clickJSON_ComputeSignature();
    void clickJSON_VerifySignature();
    void clickJSON_PayloadClear();
    void clickJSON_JWSClear();
    void clickJSON_PayloadView();
    void clickJSON_JWSView();

    void changeJSON_Payload();
    void changeJSON_JWS();

    void clickXML_BodyClear();
    void clickXML_ResClear();
    void clickXML_ResUp();

    void clickXML_MakeSign();
    void clickXML_MakeSign2();
    void clickXML_Encrypt();
    void clickXML_Encrypt2();
    void clickXML_VerifySign();
    void clickXML_Decrypt();

    void changeXML_Body();
    void changeXML_Data();

private:
    void initUI();
    void initialize();
    int getPubKey( BIN *pPubKey );
    int getCert( BIN *pCert );
    int getPriKey( BIN *pPriKey );
    int getKeyPair( BIN *pPubKey, BIN *pPriKey );
    int getPriKeyCert( BIN *pPriKey, BIN *pCert );

    int getTSP( const BIN *pSrc, BIN *pTSP );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    void setDstFile();

    ACMEObject json_obj_;
    QXmlStreamReader xml_;
    BIN cms_;
};

#endif // DOC_SIGNER_DLG_H
