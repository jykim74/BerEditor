#ifndef ABOUT_DLG_H
#define ABOUT_DLG_H

#include <QDialog>
#include "ui_about_dlg.h"

namespace Ui {
class AboutDlg;
}

class AboutDlg : public QDialog, public Ui::AboutDlg
{
    Q_OBJECT

public:
    AboutDlg(QWidget *parent = nullptr);
    ~AboutDlg();
#ifdef _AUTO_UPDATE
private slots:
    void checkUpdate();
#endif

private:
    Q_DISABLE_COPY(AboutDlg)
    QString version_label_;
    QString getBuild();
    void initialize();
};

#endif // ABOUT_DLG_H
