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

    void checkHex();
    void checkString();
    void checkShowInfo();

private:
    void initUI();

    void log( const QString strLog, bool bNL = true );
    void log( int nSpace, const QString strLog, bool bNL = true );
    void log( const QString strHead, int nSpace, const QString strValue, bool bNL = true );
    void line();
    void logBIN( int nSpace, const BIN *pData );
    void logBIN( const QString strHead, int nSpace, const BIN *pData );
    void logBIN2( int nOffset, int nSpace, const BIN *pData, bool bInfo = false );
    void logBIN2( int nOffset, const QString strHead, int nSpace, const BIN *pData, bool bInfo = false );

    void parseBER();
    void parseTTLV();

    void textHex( BerModel *pModel );
    void textString( BerModel *pModel );

    void textHex( TTLVTreeModel *pModel );
    void textString( TTLVTreeModel *pModel );

    BIN data_;
};

#endif // TEXT_VIEW_DLG_H
