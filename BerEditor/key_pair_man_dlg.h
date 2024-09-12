#ifndef KEY_PAIR_MAN_DLG_H
#define KEY_PAIR_MAN_DLG_H

#include <QDialog>
#include "ui_key_pair_man_dlg.h"
#include "js_bin.h"

namespace Ui {
class KeyPairManDlg;
}

enum DerType {
    TypePriKey = 0,
    TypePubKey,
    TypeEncPri,
    TypePriInfo,
    TypeCSR
};

class KeyPairManDlg : public QDialog, public Ui::KeyPairManDlg
{
    Q_OBJECT

public:
    explicit KeyPairManDlg(QWidget *parent = nullptr);
    ~KeyPairManDlg();

private slots:
    void showEvent(QShowEvent *event);
    void closeEvent(QCloseEvent *event );

    void keyTypeChanged( int index );

    void clickLGenKeyPair();
    void clickLDelete();
    void clickLMakeCSR();
    void clickLEncrypt();
    void clickLViewPriKey();
    void clickLViewPubKey();
    void clickLDecodePriKey();
    void clickLDecodePubKey();

    void clickLRunSign();
    void clickLRunVerify();
    void clickLRunPubEnc();
    void clickLRunPubDec();

    void changeVerison( int index );
    void clickSaveToList();
    void clickMakeCSR();

    void clickCheckKeyPair();
    void clickEncrypt();

    void clickViewCSR();
    void clickDecrypt();
    void clickClearAll();

    void viewPriKey();
    void viewPubKey();

    void findPriKey();
    void findPubKey();
    void findEncPriKey();

    void clearPriKey();
    void clearPubKey();
    void clearEncPriKey();
    void clearPriInfo();
    void clearCSR();

    void decodePriKey();
    void decodePubKey();
    void decodeEncPriKey();
    void decodePriInfo();
    void decodeCSR();

    void typePriKey();
    void typePubKey();
private:
    void initUI();
    void initialize();
    const QString getTypePathName( qint64 now_t, DerType nType );
    int Save( qint64 tTime, DerType nType, const QString strHex );
    int Save( qint64 tTime, DerType nType, const BIN *pBin );

    void loadKeyPairList();
    const QString getSelectedPath();
};

#endif // KEY_PAIR_MAN_DLG_H
