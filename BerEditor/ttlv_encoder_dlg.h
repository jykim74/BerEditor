#ifndef REQ_ENCODER_DLG_H
#define REQ_ENCODER_DLG_H

#include <QDialog>
#include "js_bin.h"
#include "ui_ttlv_encoder_dlg.h"

namespace Ui {
class TTLVEncoderDlg;
}

const QString kCMD_GET                  = "Get";
const QString kCMD_ACTIVATE             = "Activate";
const QString kCMD_CREATE               = "Create";
const QString kCMD_DESTROY              = "Destroy";
const QString kCMD_ENCRYPT              = "Encrypt";
const QString kCMD_DECRYPT              = "Decrypt";
const QString kCMD_SIGN                 = "Sign";
const QString kCMD_VERIFY               = "Verify";
const QString kCMD_HASH                 = "Hash";
const QString kCMD_REGISTER             = "Register";
const QString kCMD_CREATE_KEY_PAIR      = "CreateKeyPair";
const QString kCMD_ADD_ATTRIBUTE        = "AddAttribute";
const QString kCMD_GET_ATTRIBUTE_LIST   = "GetAttributeList";
const QString kCMD_GET_ATTRIBUTES       = "GetAttributes";
const QString kCMD_MODIFY_ATTRIBUTE     = "ModifyAttribute";
const QString kCMD_DELETE_ATTRIBUTE     = "DeleteAttribute";
const QString kCMD_LOCATE               = "Locate";
const QString kCMD_RNG_RETRIEVE         = "RNGRetrieve";
const QString kCMD_RNG_SEED             = "RNGSeed";


const QString kOBJ_SECRET_KEY           = "SecretKey";
const QString kOBJ_PRIVATE_KEY          = "PrivateKey";
const QString kOBJ_PUBLIC_KEY           = "PublicKey";
const QString kOBJ_CERTIFICATE          = "Certificate";

const QString kALG_RSA                  = "RSA";
const QString kALG_ECDSA                = "ECDSA";
const QString kALG_AES                  = "AES";

class TTLVEncoderDlg : public QDialog, public Ui::TTLVEncoderDlg
{
    Q_OBJECT

public:
    explicit TTLVEncoderDlg(QWidget *parent = nullptr);
    ~TTLVEncoderDlg();
    const QString getOutput();
    void setManage();

private slots:
    void changeType();
    void changeCmd();
    void clickEncode();
    void clickOK();

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
    void clickLocate();
    void clickRNGRetrieve();
    void clickRNGSeed();
    void clickHash();

    void changeIV();
    void changeInput();
    void changeSign();
    void changeOutput();
    void clearInput();
    void clearSign();
    void clearOutput();
    void decodeOutput();
    void clearAll();

    void findInput();
    void algChanged( int index );
    void objectTypeChanged( int index );

private:
    void initUI();
    void initialize();

    void setEnableUUID( bool bVal );
    void setEnableLen( bool bVal );
    void setEnableAttribute( bool bVal );
    void setEnableObjectType( bool bVal );
    void setEnableAlg( bool bVal );
    void setEnableOption( bool bVal );
    void setEnableHash( bool bVal );
    void setEnableMode( bool bVal );
    void setEnableIV( bool bVal );
    void setEnableInput( bool bVal );
    void setEnableSign( bool bVal );
    void setEnableAll( bool bVal );
};

#endif // REQ_ENCODER_DLG_H
