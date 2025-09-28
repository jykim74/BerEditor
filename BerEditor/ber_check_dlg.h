#ifndef BER_CHECK_DLG_H
#define BER_CHECK_DLG_H

#include <QDialog>
#include "ui_ber_check_dlg.h"
#include "js_bin.h"

namespace Ui {
class BERCheckDlg;
}

class BERCheckDlg : public QDialog, public Ui::BERCheckDlg
{
    Q_OBJECT

public:
    explicit BERCheckDlg(QWidget *parent = nullptr);
    ~BERCheckDlg();

private slots:
    void clickClear();
    void clickFileFind();
    void clickCheckFormat();
    void clickCheckType();

    void clickView();
    void clickDecode();
    void clickType();

    void checkFile();
    void changeSrcType();
    void changeSrc();

private:
    void initUI();
    void initialize();

    int readSrc( BIN *pSrc );
};

#endif // BER_CHECK_DLG_H
