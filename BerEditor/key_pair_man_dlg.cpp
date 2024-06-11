#include "key_pair_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"

KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickGenKeyPair()));
    connect( mMakeCSRBtn, SIGNAL(clicked()), this, SLOT(clickMakeCSR()));
}

KeyPairManDlg::~KeyPairManDlg()
{

}

void KeyPairManDlg::clickGenKeyPair()
{
    GenKeyPairDlg genKeyPair;
    genKeyPair.exec();
}

void KeyPairManDlg::clickMakeCSR()
{
    MakeCSRDlg makeCSR;
    makeCSR.exec();
}
