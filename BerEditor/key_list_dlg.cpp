#include "key_list_dlg.h"
#include "ui_key_list_dlg.h"
#include "key_add_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"

KeyListDlg::KeyListDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mKeyAddBtn, SIGNAL(clicked()), this, SLOT(clickKeyAdd()));
    connect( mKeyDelBtn, SIGNAL(clicked()), this, SLOT(clickKeyDel()));
    connect( mKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickKeyView()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

KeyListDlg::~KeyListDlg()
{

}

void KeyListDlg::initialize()
{

}

void KeyListDlg::clickKeyAdd()
{
    KeyAddDlg keyAdd;
    keyAdd.exec();
}

void KeyListDlg::clickKeyDel()
{

}

void KeyListDlg::clickKeyView()
{

}
