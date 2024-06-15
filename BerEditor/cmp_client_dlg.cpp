#include "cmp_client_dlg.h"
#include "auth_ref_dlg.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"

CMPClientDlg::CMPClientDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGENMBtn, SIGNAL(clicked()), this, SLOT(clickGENM()));
    connect( mIRBtn, SIGNAL(clicked()), this, SLOT(clickIR()));
    connect( mKURBtn, SIGNAL(clicked()), this, SLOT(clickKUR()));
    connect( mRRBtn, SIGNAL(clicked()), this, SLOT(clickRR()));

#if defined( Q_OS_MAC )
    mCACertViewBtn->setFixedWidth(34);
    mCACertDecodeBtn->setFixedWidth(34);
    mCACertTypeBtn->setFixedWidth(34);

    mCertViewBtn->setFixedWidth(34);
    mCertDecodeBtn->setFixedWidth(34);
    mCertTypeBtn->setFixedWidth(34);

    mPriKeyDecodeBtn->setFixedWidth(34);
    mPriKeyTypeBtn->setFixedWidth(34);

    mRequestClearBtn->setFixedWidth(34);
    mRequestDecodeBtn->setFixedWidth(34);

    mResponseClearBtn->setFixedWidth(34);
    mResponseDecodeBtn->setFixedWidth(34);

    layout()->setSpacing(5);
#endif

    initialize();
}

CMPClientDlg::~CMPClientDlg()
{

}

void CMPClientDlg::initialize()
{

}

void CMPClientDlg::findCACert()
{

}

void CMPClientDlg::viewCACert()
{

}

void CMPClientDlg::decodeCACert()
{

}

void CMPClientDlg::typeCACert()
{

}


void CMPClientDlg::findCert()
{

}

void CMPClientDlg::viewCert()
{

}

void CMPClientDlg::decodeCert()
{

}

void CMPClientDlg::typeCert()
{

}


void CMPClientDlg::findPriKey()
{

}

void CMPClientDlg::decodePriKey()
{

}

void CMPClientDlg::typePriKey()
{

}


void CMPClientDlg::clearRequest()
{

}

void CMPClientDlg::decodeRequest()
{

}


void CMPClientDlg::clearResponse()
{

}

void CMPClientDlg::decodeResponse()
{

}


void CMPClientDlg::clickGENM()
{

}

void CMPClientDlg::clickIR()
{
    AuthRefDlg authRef;
    authRef.exec();
}

void CMPClientDlg::clickKUR()
{

}

void CMPClientDlg::clickRR()
{

}
