#include "key_add_dlg.h"
#include "ui_key_add_dlg.h"

KeyAddDlg::KeyAddDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

KeyAddDlg::~KeyAddDlg()
{

}

void KeyAddDlg::clickClearAll()
{

}

void KeyAddDlg::clickOK()
{

}
