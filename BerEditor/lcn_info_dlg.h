#ifndef LCN_INFO_DLG_H
#define LCN_INFO_DLG_H

#include <QDialog>
#include "ui_lcn_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class LCNInfoDlg;
}

class LCNInfoDlg : public QDialog, public Ui::LCNInfoDlg
{
    Q_OBJECT

public:
    explicit LCNInfoDlg(QWidget *parent = nullptr);
    ~LCNInfoDlg();

private slots:
    void clickGet();
    void clickUpdate();
    void checkUseFile();

private:
    void initialize();
    bool isValidLCN( const BIN *pLCN, const char *pSID );
    int getLCN( BIN *pLCN );
    int updateLCN( const QString strEmail, const QString strKey, BIN *pLCN );
};

#endif // LCN_INFO_DLG_H
