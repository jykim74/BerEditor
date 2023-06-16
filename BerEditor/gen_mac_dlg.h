#ifndef GEN_MAC_DLG_H
#define GEN_MAC_DLG_H

#include <QDialog>
#include <QButtonGroup>
#include "ui_gen_mac_dlg.h"

namespace Ui {
class GenMacDlg;
}

class GenMacDlg : public QDialog, public Ui::GenMacDlg
{
    Q_OBJECT

public:
    explicit GenMacDlg(QWidget *parent = nullptr);
    ~GenMacDlg();

private slots:
        void mac();
        void macInit();
        void macUpdate();
        void macFinal();

        void inputClear();
        void outputClear();

        void inputChanged();
        void outputChanged();
        void keyChanged();

        void checkHMAC();
        void checkCMAC();
        void checkGMAC();

        void clickClearDataAll();
        void clickMAC();
        void clickFindSrcFile();
        void clickMACSrcFile();
private:
        void freeCTX();

        void initialize();
        void *hctx_;
        int type_;
        QButtonGroup* group_;
};

#endif // GEN_MAC_DLG_H
