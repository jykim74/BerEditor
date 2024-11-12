#ifndef MAKE_TTLV_DLG_H
#define MAKE_TTLV_DLG_H

#include <QDialog>
#include "ui_make_ttlv_dlg.h"

namespace Ui {
class MakeTTLVDlg;
}

class MakeTTLVDlg : public QDialog, public Ui::MakeTTLVDlg
{
    Q_OBJECT

public:
    explicit MakeTTLVDlg(QWidget *parent = nullptr);
    ~MakeTTLVDlg();
    QString getData();
    void setTitle( const QString strTitle );

private slots:
    void changeType( int index );
    void changeTag( const QString text );
    void changeValue();
    void changeTTLV();

    void clickOK();



private:
    void initialize();
    void makeHeader();
};

#endif // MAKE_TTLV_DLG_H
