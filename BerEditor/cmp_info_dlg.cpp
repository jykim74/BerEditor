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

    memset( &cmp_msg_, 0x00, sizeof(BIN));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

CMPInfoDlg::~CMPInfoDlg()
{
    JS_BIN_reset( &cmp_msg_ );
}

void CMPInfoDlg::setMsg( const BIN *pMsg )
{
    JS_BIN_reset( &cmp_msg_ );
    JS_BIN_copy( &cmp_msg_, pMsg );
}
