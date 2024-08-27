#ifndef GEN_KEY_PAIR_DLG_H
#define GEN_KEY_PAIR_DLG_H

#include <QDialog>
#include "ui_gen_key_pair_dlg.h"
#include "js_bin.h"

namespace Ui {
class GenKeyPairDlg;
}

class GenKeyPairDlg : public QDialog, public Ui::GenKeyPairDlg
{
    Q_OBJECT

public:
    explicit GenKeyPairDlg(QWidget *parent = nullptr);
    ~GenKeyPairDlg();

    const QString getPriKeyHex();
    const QString getPubKeyHex();

    void setRegInfo( const QString strRegInfo );
    void setFixName( const QString strName );

private slots:
    void clickRSA();
    void clickECDSA();
    void clickDSA();
    void clickEdDSA();

    void clickOK();

private:
    void initialize();

    BIN pri_key_;
    BIN pub_key_;
};

#endif // GEN_KEY_PAIR_DLG_H
