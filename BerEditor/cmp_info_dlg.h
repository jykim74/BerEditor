#ifndef CMP_INFO_DLG_H
#define CMP_INFO_DLG_H

#include <QDialog>
#include "ui_cmp_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class CMPInfoDlg;
}

class CMPInfoDlg : public QDialog, public Ui::CMPInfoDlg
{
    Q_OBJECT

public:
    explicit CMPInfoDlg(QWidget *parent = nullptr);
    ~CMPInfoDlg();

    void setMsg( const BIN *pMsg );

private:
    void initUI();
    void initialize();

    void setCMPData( int nType, void *pData );

    BIN cmp_msg_;
};

#endif // CMP_INFO_DLG_H
