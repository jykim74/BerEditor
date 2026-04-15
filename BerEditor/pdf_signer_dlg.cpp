#include "pdf_signer_dlg.h"

#ifdef PDF_SIGN

PDFSignerDlg::PDFSignerDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PDFSignerDlg::~PDFSignerDlg()
{

}

#endif
