#ifndef DATA_ENCODER_DLG_H
#define DATA_ENCODER_DLG_H

#include <QDialog>

namespace Ui {
class DataEncoderDlg;
}

class DataEncoderDlg : public QDialog
{
    Q_OBJECT

public:
    explicit DataEncoderDlg(QWidget *parent = nullptr);
    ~DataEncoderDlg();

private:
    Ui::DataEncoderDlg *ui;
};

#endif // DATA_ENCODER_DLG_H
