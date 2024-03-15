#ifndef VID_DLG_H
#define VID_DLG_H

#include <QDialog>
#include "ui_vid_dlg.h"

namespace Ui {
class VIDDlg;
}

class VIDDlg : public QDialog, public Ui::VIDDlg
{
    Q_OBJECT

public:
    explicit VIDDlg(QWidget *parent = nullptr);
    ~VIDDlg();

private slots:
    void changeSSN( const QString& text );
    void changeRand( const QString& text );
    void changeVID();
    void changeHashContent();

    void clickMakeVID();
    void clickVerifyVID();
    void clickClearAll();
    void clickDecodeVID();
    void clickDecodeHashContent();

private:
    void initialize();
};

#endif // VID_DLG_H
