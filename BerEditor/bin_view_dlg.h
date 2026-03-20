#ifndef BIN_VIEW_DLG_H
#define BIN_VIEW_DLG_H

#include <QDialog>
#include "ui_bin_view_dlg.h"
#include "js_bin.h"

namespace Ui {
class BinViewDlg;
}

class BinViewDlg : public QDialog, public Ui::BinViewDlg
{
    Q_OBJECT

public:
    explicit BinViewDlg(QWidget *parent = nullptr);
    ~BinViewDlg();
    void setData( const BIN *pData );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void clickPrint();
    void clickPrintPreview();
    void clickFind();

    void checkBase64();
    void checkHex();
    void checkRaw();

    void checkPEM();

private:
    void initUI();
    void initialize();
    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );

    void encodeBase64();
    void encodeHex();
    void encodeData();

    BIN data_;
};

#endif // BIN_VIEW_DLG_H
