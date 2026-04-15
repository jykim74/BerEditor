#ifndef PDF_SIGNER_DLG_H
#define PDF_SIGNER_DLG_H

#include <QDialog>
#include "ui_pdf_signer_dlg.h"

#ifdef PDF_SIGN

namespace Ui {
class PDFSignerDlg;
}


class PDFSignerDlg : public QDialog, public Ui::PDFSignerDlg
{
    Q_OBJECT

public:
    explicit PDFSignerDlg(QWidget *parent = nullptr);
    ~PDFSignerDlg();

private:

};

#endif

#endif // PDF_SIGNER_DLG_H
