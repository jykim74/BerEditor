#ifndef TEXT_VIEW_DLG_H
#define TEXT_VIEW_DLG_H

#include <QDialog>
#include <QPrinter>
#include "js_bin.h"

#include "ui_text_view_dlg.h"
#include "ber_model.h"
#include "ttlv_tree_model.h"

namespace Ui {
class TextViewDlg;
}

class TextViewDlg : public QDialog, public Ui::TextViewDlg
{
    Q_OBJECT

public:
    explicit TextViewDlg(QWidget *parent = nullptr);
    ~TextViewDlg();
    void setData( const BIN *pData );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void clickPrint();
    void printPreview(QPrinter *printer);
    void filePrintPreview();

    void clickFind();

    void checkCertUtil();
    void checkOpenSSL();

private:
    void initUI();

    void log( const QString strLog, bool bNL = true );
    void line();

    void parseBER();
    void parseTTLV();

    void textCertUtil( BerModel *pModel );
    void textOpenSSL( BerModel *pModel );

    void textCertUtil( TTLVTreeModel *pModel );
    void textOpenSSL( TTLVTreeModel *pModel );

    BIN data_;
};

#endif // TEXT_VIEW_DLG_H
