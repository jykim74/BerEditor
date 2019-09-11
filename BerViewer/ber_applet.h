#ifndef BER_APPLET_H
#define BER_APPLET_H

#include <QObject>
#include <QMessageBox>

class SettingsDlg;
class SettingsMgr;
class DataEncoderDlg;
class GenHashDlg;
class GenHmacDlg;
class OIDInfoDlg;
class EncDecDlg;
class SignVerifyDlg;
class RSAEncDecDlg;
class GenOTPDlg;
class AboutDlg;

class MainWindow;

class BerApplet : public QObject
{
    Q_OBJECT
public:
    BerApplet(QObject *parent = nullptr);
    ~BerApplet();

    void start();

    SettingsDlg *settingsDlg() { return settings_dlg_; };
    SettingsMgr *settingsMgr() { return settings_mgr_; };
    DataEncoderDlg *dataEncoderDlg() { return data_encoder_dlg_; };
    GenHashDlg *genHashDlg() { return gen_hash_dlg_; };
    GenHmacDlg *genHmacDlg() { return gen_hmac_dlg_; };
    OIDInfoDlg *oidInfoDlg() { return oid_info_dlg_; };
    EncDecDlg *encDecDlg() { return enc_dec_dlg_; };
    SignVerifyDlg *signVerifyDlg() { return sign_verify_dlg_; };
    RSAEncDecDlg *rsaEncDecDlg() { return rsa_enc_dec_dlg_; };
    GenOTPDlg *genOTPDlg() { return gen_otp_dlg_; };
    AboutDlg *aboutDlg() { return about_dlg_; };

    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    bool closingDown() { return in_exit_ || about_to_quit_; };

    void restartApp();

signals:

public slots:

private:
    Q_DISABLE_COPY(BerApplet)

    MainWindow* main_win_;
    SettingsDlg* settings_dlg_;
    SettingsMgr* settings_mgr_;
    DataEncoderDlg* data_encoder_dlg_;
    GenHashDlg* gen_hash_dlg_;
    GenHmacDlg* gen_hmac_dlg_;
    OIDInfoDlg* oid_info_dlg_;
    EncDecDlg* enc_dec_dlg_;
    SignVerifyDlg* sign_verify_dlg_;
    RSAEncDecDlg* rsa_enc_dec_dlg_;
    GenOTPDlg*    gen_otp_dlg_;

    AboutDlg* about_dlg_;

    bool started_;
    bool in_exit_;
    bool about_to_quit_;
};

extern BerApplet *berApplet;

#define STR(s)          #s
#define STRINGIZE(x)    STR(x)

#endif // BER_APPLET_H
