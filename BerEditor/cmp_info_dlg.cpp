#include <QDialog>
#include <QLayout>

#include "cmp_info_dlg.h"
#include "js_cmp.h"
#include "js_cmp_srv.h"

#include "ber_applet.h"
#include "mainwindow.h"

CMPInfoDlg::CMPInfoDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

CMPInfoDlg::~CMPInfoDlg()
{

}
