#ifndef REQ_ENCODER_DLG_H
#define REQ_ENCODER_DLG_H

#include <QDialog>
#include "js_bin.h"
#include "ui_ttlv_encoder_dlg.h"

namespace Ui {
class TTLVEncoderDlg;
}

class TTLVEncoderDlg : public QDialog, public Ui::TTLVEncoderDlg
{
    Q_OBJECT

public:
    explicit TTLVEncoderDlg(QWidget *parent = nullptr);
    ~TTLVEncoderDlg();
    BIN& getData() { return data_; };

private slots:
    void clickGet();
    void clickActivate();
    void clickCreate();
    void clickDestroy();
    void clickEncrypt();
    void clickDecrypt();
    void clickSign();
    void clickVerify();
    void clickRegister();
    void clickCreateKeyPair();

    void clickGetAttributeList();
    void clickAddAttribute();
    void clickGetAttributes();
    void clickModifyAttribute();
    void clickDeleteAttribute();
    void clickRevoke();
    void clickMAC();
    void clickLocate();
    void clickDeriveKey();
    void clickCreateSplitKey();
    void clickJoinSplitKey();
    void clickRNGRetrieve();
    void clickRNGSeed();
    void clickHash();


    void findInput();
    void algChanged( int index );

private:
    void initialize();
    BIN data_;
};

#endif // REQ_ENCODER_DLG_H
