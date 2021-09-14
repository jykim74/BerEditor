#ifndef INSERT_BER_DLG_H
#define INSERT_BER_DLG_H

#include <QDialog>
#include "ui_insert_ber_dlg.h"

namespace Ui {
class InsertBerDlg;
}

class InsertBerDlg : public QDialog, public Ui::InsertBerDlg
{
    Q_OBJECT

public:
    explicit InsertBerDlg(QWidget *parent = nullptr);
    ~InsertBerDlg();
    QString getData();

private slots:
    void runInsert();
    void checkConstructed();
    void headerChanged( const QString& text );
    void valueChanged();
    void classChanged(int index);
    void primitiveChanged(int index );

private:
    void initialize();
    void makeHeader();
};

#endif // INSERT_BER_DLG_H