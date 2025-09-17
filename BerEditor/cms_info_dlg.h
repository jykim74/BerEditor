#ifndef CMS_INFO_DLG_H
#define CMS_INFO_DLG_H

#include <QDialog>
#include "ui_cms_info_dlg.h"
#include "js_bin.h"
#include "js_pkcs7.h"
#include "js_cms.h"

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
    explicit CMSInfoDlg(QWidget *parent = nullptr );
    ~CMSInfoDlg();

    void setPKCS7();
    void setCMS( const QString strPath );
    void setCMS( const BIN *pCMS, const QString strTitle = "" );

private slots:
    void dataChanged();
    void clickDecode();

    void clickDataField(QModelIndex index);
    void clickSignerField(QModelIndex index);
    void clickRecipField(QModelIndex index);

    void clickViewCert();
    void clickViewCRL();

    void clickViewTSP();
    void clickViewTST();

private:
    void initUI();
    void setTitle( const QString strName );

    void setSignerInfo( const JP7SignerInfoList *pSignerList );
    void setRecipInfo( const JP7RecipInfoList *pRecipList );

    void setSignerInfoCMS( const JSignerInfoList *pSignerList );
    void setRecipInfoCMS( const JRecipInfoList *pRecipList );

    void setSigned();
    void setEnveloped();
    void setSignedCMS();
    void setEnvelopedCMS();
    void setSignedAndEnveloped();
    void setData();
    void setDigest();
    void setEncrypted();

    BIN cms_bin_;
    int cms_type_;
    BIN tsp_bin_;
    QString cms_path_;
    bool is_cms_;
};

#endif // CMS_INFO_DLG_H
