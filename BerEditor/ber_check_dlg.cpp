#include "ber_check_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"

#include "js_pki.h"
#include "js_pki_tools.h"

const QStringList sTypeList = {
    JS_PKI_BER_NAME_CERTIFICATE, JS_PKI_BER_NAME_CRL, JS_PKI_BER_NAME_CSR,
    JS_PKI_BER_NAME_PUB_KEY, JS_PKI_BER_NAME_PRI_KEY, JS_PKI_BER_NAME_PRI_KEY_INFO,
    JS_PKI_BER_NAME_PRI_ENC_KEY, JS_PKI_BER_NAME_CMS, JS_PKI_BER_NAME_PKCS7
};

BERCheckDlg::BERCheckDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearBtn, SIGNAL(clicked(bool)), this, SLOT(clickClear()));
    connect( mFilleFindBtn, SIGNAL(clicked(bool)), this, SLOT(clickFileFind()));
    connect( mFormatCheckBtn, SIGNAL(clicked(bool)), this, SLOT(clickCheckFormat()));
    connect( mTypeCheckBtn, SIGNAL(clicked(bool)), this, SLOT(clickCheckType()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    initialize();
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

BERCheckDlg::~BERCheckDlg()
{

}

void BERCheckDlg::initUI()
{
    mFormatCombo->addItems( sTypeList );
    mSrcTypeCombo->addItems( kDataBinTypeList );
}

void BERCheckDlg::initialize()
{

}

void BERCheckDlg::clickClear()
{

}

void BERCheckDlg::clickFileFind()
{

}


void BERCheckDlg::clickCheckFormat()
{

}

void BERCheckDlg::clickCheckType()
{

}
