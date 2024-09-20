#ifndef CMS_INFO_DLG_H
#define CMS_INFO_DLG_H

#include <QDialog>
#include "ui_cms_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class CMSInfoDlg;
}

class CMSInfoDlg : public QDialog, public Ui::CMSInfoDlg
{
    Q_OBJECT

public:
    explicit CMSInfoDlg(QWidget *parent = nullptr);
    ~CMSInfoDlg();

    void setCMS( const BIN *pCMS );

private slots:
    void dataChanged();

private:
    void initUI();

    void setSigned();
    void setEnveloped();
    void setSignedAndEnveloped();

    BIN cms_bin_;
    int cms_type_;
};

#endif // CMS_INFO_DLG_H
