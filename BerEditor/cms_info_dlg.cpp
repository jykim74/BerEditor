#include "cms_info_dlg.h"

#include "js_pki.h"
#include "js_pkcs7.h"

#include "common.h"

CMSInfoDlg::CMSInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    memset( &cms_bin_, 0x00, sizeof(BIN));

    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDataText, SIGNAL(textChanged()), this, SLOT(dataChanged()));
}

CMSInfoDlg::~CMSInfoDlg()
{
    JS_BIN_reset( &cms_bin_ );
}

void CMSInfoDlg::setCMS( const BIN *pCMS )
{
    int ret = 0;
    JSignedInfo sSignedInfo;

    memset( &sSignedInfo, 0x00, sizeof(JSignedInfo));

    JS_BIN_reset( &cms_bin_ );
    JS_BIN_copy( &cms_bin_, pCMS );

    ret = JS_PKCS7_getSignedData( &cms_bin_, &sSignedInfo );

    mVersionText->setText( QString("%1").arg( sSignedInfo.nVersion ));
    mDataText->setPlainText( getHexString( &sSignedInfo.binContent ));

    JS_PKCS7_resetSignedInfo( &sSignedInfo );
}

void CMSInfoDlg::dataChanged()
{
    QString strData = mDataText->toPlainText();

    QString strLen = getDataLenString( DATA_HEX, strData );
    mDataLenText->setText( QString("%1").arg( strLen ));
}
