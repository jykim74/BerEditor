#ifndef TST_INFO_DLG_H
#define TST_INFO_DLG_H

#include <QDialog>
#include "ui_tst_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class TSTInfoDlg;
}

class TSTInfoDlg : public QDialog, public Ui::TSTInfoDlg
{
    Q_OBJECT

public:
    explicit TSTInfoDlg(QWidget *parent = nullptr);
    ~TSTInfoDlg();

    void setTST( const BIN *pTST );

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );
    void clickDataDecode();

private:
    BIN tst_;

    void initUI();
    void initialize();
    void clearTable();
};

#endif // TST_INFO_DLG_H
