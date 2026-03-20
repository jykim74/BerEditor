#ifndef TEXT_VIEW_DLG_H
#define TEXT_VIEW_DLG_H

#include <QDialog>
#include "ui_text_view_dlg.h"

namespace Ui {
class TextViewDlg;
}

class TextViewDlg : public QDialog, public Ui::TextViewDlg
{
    Q_OBJECT

public:
    explicit TextViewDlg(QWidget *parent = nullptr);
    ~TextViewDlg();

private:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void clickPrint();
    void clickPrintPreview();
    void clickFind();

private:
    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );

};

#endif // TEXT_VIEW_DLG_H
