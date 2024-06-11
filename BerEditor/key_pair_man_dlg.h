#ifndef KEY_PAIR_MAN_DLG_H
#define KEY_PAIR_MAN_DLG_H

#include <QDialog>
#include "ui_key_pair_man_dlg.h"

namespace Ui {
class KeyPairManDlg;
}

class KeyPairManDlg : public QDialog, public Ui::KeyPairManDlg
{
    Q_OBJECT

public:
    explicit KeyPairManDlg(QWidget *parent = nullptr);
    ~KeyPairManDlg();

private slots:
    void changeVerison( int index );

    void clickGenKeyPair();
    void clickMakeCSR();

    void clickCheckKeyPair();
    void clickEncrypt();
    void clickEncodePFX();
    void clickViewCert();
    void clickViewCSR();
    void clickDecrypt();
    void clickDecodePFX();
    void clickClearAll();

    void findSavePath();
    void findPriKey();
    void findPubKey();
    void findCert();
    void findEncPriKey();
    void findPFX();

    void clearPriKey();
    void clearPubKey();
    void clearCert();
    void clearEncPriKey();
    void clearPFX();
    void clearCSR();

    void decodePriKey();
    void decodePubKey();
    void decodeCert();
    void decodeEncPriKey();
    void decodePFX();
    void decodeCSR();

    void typePriKey();
    void typePubKey();
    void typeCert();
private:

    void initialize();
};

#endif // KEY_PAIR_MAN_DLG_H
