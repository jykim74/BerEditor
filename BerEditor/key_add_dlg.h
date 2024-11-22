#ifndef KEY_ADD_DLG_H
#define KEY_ADD_DLG_H

#include <QDialog>
#include "js_bin.h"
#include "ui_key_add_dlg.h"

namespace Ui {
class KeyAddDlg;
}

class KeyAddDlg : public QDialog, public Ui::KeyAddDlg
{
    Q_OBJECT

public:
    explicit KeyAddDlg(QWidget *parent = nullptr);
    ~KeyAddDlg();
    int readFile( const QString strName );
    int setHSM( const BIN *pID );
    void setReadOnly();
    void setTitle( const QString strTitle );
    const QString getResKey() { return res_key_; };

private slots:
    void clickClearAll();
    void clickOK();
    void checkHSM();

    void clickRandKey();
    void changeKeyType();
    void changeIVType();
    void changeType();

private:
    void initUI();
    void initialize();

    QString res_key_;
};

#endif // KEY_ADD_DLG_H
