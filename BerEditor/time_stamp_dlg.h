#ifndef TIME_STAMP_DLG_H
#define TIME_STAMP_DLG_H

#include <QDialog>
#include "ui_time_stamp_dlg.h"

namespace Ui {
class TimeStampDlg;
}

class TimeStampDlg : public QDialog, public Ui::TimeStampDlg
{
    Q_OBJECT

public:
    explicit TimeStampDlg(QWidget *parent = nullptr);
    ~TimeStampDlg();

private slots:
    void clickOK();
    void checkAuth();

private:
    void initUI();
    void initialize();

    QStringList getUsedURL();
    void setUsedURL( const QString strURL );
};

#endif // TIME_STAMP_DLG_H
