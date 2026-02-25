#ifndef DOC_SIGNER_DLG_H
#define DOC_SIGNER_DLG_H

#include <QDialog>
#include <QXmlStreamReader>
#include "ui_doc_signer_dlg.h"
#include "acme_object.h"

#include "js_bin.h"

const QString kCMSCmdData = "Data";
const QString kCMSCmdDigest = "Digest";
const QString kCMSCmdSignedData = "Signed";
const QString kCMSCmdEnvelopedData = "Enveloped";
const QString kCMSCmdAddSigned = "Add Signed";
const QString kCMSCmdGetData = "GetData";
const QString kCMSCmdGetDigest = "GetDigest";
const QString kCMSCmdVerifyData = "Verify";
const QString kCMSCmdDevelopedData = "Developed";

const QStringList kCMSEncodeList = {
    kCMSCmdSignedData, kCMSCmdEnvelopedData, kCMSCmdAddSigned, kCMSCmdData, kCMSCmdDigest
};

const QStringList kCMSDecodeList = {
    kCMSCmdVerifyData, kCMSCmdDevelopedData, kCMSCmdGetData, kCMSCmdGetDigest
};

namespace Ui {
class DocSignerDlg;
}

const int kIndexCMS     = 0;
const int kIndexJSON    = 1;
const int kIndexXML     = 2;
const int kIndexPDF     = 3;

class DocSignerDlg : public QDialog, public Ui::DocSignerDlg
{
    Q_OBJECT

public:
    explicit DocSignerDlg(QWidget *parent = nullptr);
    ~DocSignerDlg();

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void clickClearAll();
    void changeSignerTab();
    void checkUseCertMan();

    void checkCMSEncode();
    void checkCMSDecode();
    void checkCMSAutoDetect();

    void checkSrcFile();
    void checkDstFile();

    void findSrcPath();
    void findDstPath();

    void checkUseTSP();
    void clickTSP();

    void changeCMSSrc();
    void changeCMSOutput();

    void clickCMSOutputUp();

    void clickCMSSrcClear();
    void clickCMSSrcView();
    void clickCMSSrcType();
    void clickCMSSrcDecode();

    void clickCMSOutputType();
    void clickCMSOutputClear();
    void clickCMSOutputView();
    void clickCMSOutputDecode();

    void changeCMSCmd();
    void clickCMSRun();
    void clickCMSExport();

    void clickCMSMakeSign();
    void clickCMSVerifySign();
    void clickCMSEnvelopedData();
    void clickCMSDevelopedData();

    void clickCMSMakeData();
    void clickCMSMakeDigest();
    void clickCMSAddSign();

    void clickCMSGetData();
    void clickCMSGetDigest();


    void clickJSON_CheckObject();
    void clickJSON_ComputeSignature();
    void clickJSON_VerifySignature();
    void clickJSON_PayloadClear();
    void clickJSON_JWSClear();
    void clickJSON_JWSUp();
    void clickJSON_PayloadView();
    void clickJSON_JWSView();
    void clickJSON_Export();

    void changeJSON_Payload();
    void changeJSON_JWS();

    void checkXML_UseTemplate();
    void clickXML_BodyClear();
    void clickXML_ResClear();
    void clickXML_ResUp();

    void clickXML_MakeSign();
    void clickXML_Encrypt();
    void clickXML_VerifySign();
    void clickXML_Decrypt();

    void clickXML_Check();
    void checkXML_Sign();
    void checkXML_Encrypt();
    void clickXML_Make();
    void clickXML_Verify();

    void clickXML_Export();

    void changeXML_Body();
    void changeXML_Data();
    void changeXML_Res();

#ifdef PDF_SIGN
    void checkPDFSign();
    void checkPDFEnc();
    void checkPDFNameSubjectDN();

    void clickPDF_GetInfo();
    void clickPDF_TSP();
    void clickPDF_MakeSign();
    void clickPDF_VerifySign();
    void clickPDF_ClearInfo();
    void clickPDF_Encrypt();
    void clickPDF_Decrypt();

    void clickPDF_ViewCMS();
    void clickPDF_ExportCMS();
    void clickPDF_Make();
    void clickPDF_Verify();
#endif

private:
    void initUI();
    void initialize();

    int readCMSSrc( BIN *pData );
    int readCMSOutput( BIN *pData );

    int getPubKey( BIN *pPubKey );
    int getCert( BIN *pCert );
    int getPriKey( BIN *pPriKey, BIN *pCert = NULL );
    int getKeyPair( BIN *pPubKey, BIN *pPriKey );
    int getPriKeyCert( BIN *pPriKey, BIN *pCert );

    int getTSP( const BIN *pSrc, BIN *pTSP );

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    void setDstFile();

    void setEnableXMLData( bool bVal );
    int getCMSFlags();

    ACMEObject json_obj_;
    QXmlStreamReader xml_;
    BIN cms_;
};

#endif // DOC_SIGNER_DLG_H
