#ifndef KEY_MAN_DLG_H
#define KEY_MAN_DLG_H

#include <QDialog>
#include "ui_key_man_dlg.h"

namespace Ui {
class KeyManDlg;
}

class KeyManDlg : public QDialog, public Ui::KeyManDlg
{
    Q_OBJECT

public:
    explicit KeyManDlg(QWidget *parent = nullptr);
    ~KeyManDlg();

private slots:
    void PBKDF();
    void passwordChanged();
    void saltChanged();
    void keyValueChanged();

    void clickWrap();
    void clickUnwrap();
    void clickClear();
    void clickChange();

    void clickOutputClear();

    void clickKeyWrapGenKEK();

    void srcChanged();
    void dstChanged();
    void kekChanged( const QString& text );
    void clickClearDataAll();

private:
    void initialize();
};

#endif // KEY_MAN_DLG_H
