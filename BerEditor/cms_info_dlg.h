#ifndef CMS_INFO_DLG_H
#define CMS_INFO_DLG_H

#include <QDialog>
#include "ui_cms_info_dlg.h"
#include "js_bin.h"

#define JS_CMS_DATA_IDX     0
#define JS_CMS_CERT_IDX     1
#define JS_CMS_CRL_IDX      2
#define JS_CMS_SIGNER_IDX   3
#define JS_CMS_RECIP_IDX    4

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
    void clickDecodeData();

    void clickDataField(QModelIndex index);
    void clickSignerField(QModelIndex index);
    void clickRecipField(QModelIndex index);

    void clickViewCert();
    void clickViewCRL();

private:
    void initUI();

    void setSigned();
    void setEnveloped();
    void setSignedAndEnveloped();
    void setData();
    void setDigest();
    void setEncrypted();

    BIN cms_bin_;
    int cms_type_;
};

#endif // CMS_INFO_DLG_H
