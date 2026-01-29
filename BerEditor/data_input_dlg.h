#ifndef DATA_INPUT_DLG_H
#define DATA_INPUT_DLG_H

#include <QDialog>
#include "ui_data_input_dlg.h"
#include "js_bin.h"

namespace Ui {
class DataInputDlg;
}

class DataInputDlg : public QDialog, public Ui::DataInputDlg
{
    Q_OBJECT

public:
    explicit DataInputDlg(QWidget *parent = nullptr);
    ~DataInputDlg();

    int getData( BIN *pData );
    void setHead( const QString strLabel );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void changeData();
    void clearData();
    void clickOK();

private:
    void initUI();
};

#endif // DATA_INPUT_DLG_H
