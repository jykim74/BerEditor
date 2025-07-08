#ifndef REVOKE_REASON_DLG_H
#define REVOKE_REASON_DLG_H

#include <QDialog>
#include "ui_revoke_reason_dlg.h"

namespace Ui {
class RevokeReasonDlg;
}

class RevokeReasonDlg : public QDialog, public Ui::RevokeReasonDlg
{
    Q_OBJECT

public:
    explicit RevokeReasonDlg(QWidget *parent = nullptr);
    ~RevokeReasonDlg();

private slots:
    void clickOK();
    void changeReason( int index );

private:
    void initUI();
};

#endif // REVOKE_REASON_DLG_H
