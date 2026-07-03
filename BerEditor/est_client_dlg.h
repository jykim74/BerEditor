#ifndef EST_CLIENT_DLG_H
#define EST_CLIENT_DLG_H

#include <QDialog>
#include "ui_est_client_dlg.h"
#include "js_bin.h"

namespace Ui {
class ESTClientDlg;
}

const QString kEST_CACerts = "cacerts";
const QString kEST_SimpleEnroll = "simpleenroll";
const QString kEST_SimpleReenroll = "simplereenroll";
const QString kEST_FullCMC = "fullcmc";
const QString kEST_ServerKeyGen = "serverkeygen";
const QString kEST_CSRAttrs = "csrattrs";

class ESTClientDlg : public QDialog, public Ui::ESTClientDlg
{
    Q_OBJECT

public:
    explicit ESTClientDlg(QWidget *parent = nullptr);
    ~ESTClientDlg();

private slots:
    void clickClearURL();
    void changeCmd();
    void clickMake();

    void clickMakeCACerts();
    void clickMakeSimpleEnroll();
    void clickMakeSimpleReenroll();
    void clickMakeFullCMC();
    void clickMakeServerKeyGen();
    void clickMakeCSRAttrs();

    void findCACert();
    void findCert();
    void findPriKey();

    void typeCACert();
    void typeCert();
    void typePriKey();

    void viewCACert();
    void viewCert();
    void viewPriKey();

    void decodeCACert();
    void decodeCert();
    void decodePriKey();

    void decodeRequest();
    void decodeResponse();

    void clearRequest();
    void clearResponse();

    void requestChanged();
    void responseChanged();

    void clickClearAll();
    void clickGetCA();
    void clickSend();
    void clickVerify();

    void checkEncPriKey();
private:
    void initUI();
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
    int readPrivateKey( BIN *pPriKey );

    int getCA( BIN *pCA );
    void savePriKeyCert( const BIN *pPriKey, const BIN *pCert );
};

#endif // EST_CLIENT_DLG_H
