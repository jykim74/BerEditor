#ifndef X509_COMPARE_DLG_H
#define X509_COMPARE_DLG_H

#include <QDialog>
#include "ui_x509_compare_dlg.h"
#include "js_bin.h"
#include "js_pki_x509.h"

namespace Ui {
class X509CompareDlg;
}

class X509CompareDlg : public QDialog, public Ui::X509CompareDlg
{
    Q_OBJECT

public:
    explicit X509CompareDlg(QWidget *parent = nullptr);
    ~X509CompareDlg();

private slots:
    void changeType();

    void clickAFind();
    void clickBFind();
    void clickClear();
    void clickCompare();

    void clickShowInfo();
    void clickCompareTable( QModelIndex index );
    void dblClickTable();

    void clickViewA();
    void clickDecodeA();

    void clickViewB();
    void clickDecodeB();

private:
    void initUI();
    void initialize();

    int compareExt( const JExtensionInfoList *pAExtList, const JExtensionInfoList *pBExtList );
    int compareCert();
    int compareCRL();
    int compareCSR();

    void logA( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elogA( const QString strLog );

    void logB( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elogB( const QString strLog );

    void logAB( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elogAB( const QString strLog );

    void moveStartA();
    void moveStartB();
    void moveStartAB();

private:
    BIN A_bin_;
    BIN B_bin_;
    QString cur_type_ = "";
};

#endif // X509_COMPARE_DLG_H
