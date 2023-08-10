#include <QDateTime>

#include "lcn_info_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"

#include "js_license.h"
#include "js_http.h"
#include "js_cc.h"


LCNInfoDlg::LCNInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(clickGet()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mUseFileCheck, SIGNAL(clicked()), this, SLOT(checkUseFile()));

    initialize();
}

LCNInfoDlg::~LCNInfoDlg()
{

}

void LCNInfoDlg::initialize()
{
    int ret = 0;
    BIN binLCN = {0,0};
    JS_LICENSE_INFO sInfo;

    QString strEmail = berApplet->settingsMgr()->getEmail();
    QString strLicense = berApplet->settingsMgr()->getLicense();

    mEmailText->setText( strEmail );

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( strLicense.length() <= 0 )
        mCurGroup->setEnabled( false );

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binLCN );

    if( JS_LCN_ParseBIN( &binLCN, &sInfo ) == 0 )
    {
        QDateTime issueTime = QDateTime::fromString( sInfo.sIssued, LICENSE_TIME_FORMAT);
        QDateTime expireTime = QDateTime::fromString( sInfo.sExpire, LICENSE_TIME_FORMAT );

        mCurEmailText->setText( sInfo.sUser );
        mCurIssueDateText->setText( issueTime.toString( "yyyy-MM-dd HH:mm:ss") );
        mCurExpireDateText->setText( expireTime.toString( "yyyy-MM-dd HH:mm:ss") );

        ret = JS_LCN_IsValid( &sInfo, LICENSE_PRODUCT_BEREDITOR_NAME, sInfo.sSID, time(NULL) );
        if( ret == LICENSE_VALID )
            mCurGroup->setEnabled( true );
        else
            mCurGroup->setEnabled( false );
    }
    else
    {
        mCurGroup->setEnabled( false );
    }

//    mReqGroup->setEnabled( !mCurGroup->isEnabled() );
    mUpdateBtn->setEnabled( mCurGroup->isEnabled() );

    JS_BIN_reset( &binLCN );
}

bool LCNInfoDlg::isValidLCN( const BIN *pLCN, const char *pSID )
{
    int ret = 0;
    JS_LICENSE_INFO sInfo;

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_LCN_ParseBIN( pLCN, &sInfo );
    if( ret != 0 ) return false;

    ret = JS_LCN_IsValid( &sInfo, LICENSE_PRODUCT_BEREDITOR_NAME, pSID, time(NULL) );
    if( ret == LICENSE_VALID ) return true;

    return false;
}

int LCNInfoDlg::getLCN( BIN *pLCN )
{
    int ret = 0;
    int status = 0;
    QString strURL;
    JNameValList *pParamList = NULL;
    char *pRsp = NULL;
    JCC_NameVal sNameVal;

    QString strEmail = mEmailText->text();
    QString strKey = mKeyText->text();

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    strURL = "http://127.0.0.1";
    strURL += JS_CC_PATH_LICENSE;

    JS_UTIL_createNameValList2( "email", strEmail.toStdString().c_str(), &pParamList );
    JS_UTIL_appendNameValList2( pParamList, "key", strKey.toStdString().c_str() );

    ret = JS_HTTP_requestResponse(
                strURL.toStdString().c_str(),
                NULL,
                NULL,
                JS_HTTP_METHOD_GET,
                pParamList,
                NULL,
                NULL,
                &status,
                &pRsp );

    if( status != JS_HTTP_STATUS_OK)
    {
        berApplet->elog( QString("Get ret:%1 status: %2").arg( ret ).arg( status ));
        return -1;
    }

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue )
    {
        JS_BIN_decodeHex( sNameVal.pValue, pLCN );
    }

    return 0;
}

int LCNInfoDlg::updateLCN( const QString strEmail, const QString strKey, BIN *pLCN )
{
    int ret = 0;
    int status = 0;
    QString strURL;
    JNameValList *pParamList = NULL;
    char *pRsp = NULL;
    JCC_NameVal sNameVal;

    memset( &sNameVal, 0x00, sizeof(sNameVal));

    strURL = "http://127.0.0.1";
    strURL += JS_CC_PATH_LICENSE;
    strURL += "/update";

    JS_UTIL_createNameValList2( "email", strEmail.toStdString().c_str(), &pParamList );
    JS_UTIL_appendNameValList2( pParamList, "key", strKey.toStdString().c_str() );

    ret = JS_HTTP_requestResponse(
                strURL.toStdString().c_str(),
                NULL,
                NULL,
                JS_HTTP_METHOD_GET,
                pParamList,
                NULL,
                NULL,
                &status,
                &pRsp );

    if( status != JS_HTTP_STATUS_OK)
    {
        berApplet->elog( QString("Get ret:%1 status: %2").arg( ret ).arg( status ));
        return -1;
    }

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue )
    {
        JS_BIN_decodeHex( sNameVal.pValue, pLCN );
    }

    return 0;
}

void LCNInfoDlg::clickGet()
{
    int ret = 0;
    BIN binLCN = {0,0};
    JS_LICENSE_INFO sInfo;
    QString strErr;

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( mUseFileCheck->isChecked() )
    {
        QString strFile = findFile( this, JS_FILE_TYPE_ALL, berApplet->curFolder() );

        if( strFile.length() > 0 )
        {
            JS_BIN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binLCN );
        }
    }
    else
    {
        ret = getLCN( &binLCN );
        if( ret != 0 )
        {
            strErr = tr( "fail to get license:%1").arg( ret );
            berApplet->elog( strErr );
            berApplet->warningBox( strErr, this );
            goto end;
        }
    }

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_LCN_ParseBIN( &binLCN, &sInfo );
    if( ret != 0 )
    {
        strErr = tr( "fail to parse license:%1").arg( ret );
        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
        goto end;
    }

    ret = JS_LCN_IsValid( &sInfo, LICENSE_PRODUCT_BEREDITOR_NAME, sInfo.sSID, time(NULL) );
    if( ret != LICENSE_VALID )
    {
        strErr = tr("license is not valid:%1").arg(ret);

        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
        ret = -1;
        goto end;
    }

    berApplet->settingsMgr()->setEmail( sInfo.sUser );
    berApplet->settingsMgr()->setLicense( getHexString( &binLCN ));
    ret = 0;

end :
    JS_BIN_reset( &binLCN );

    if( ret == 0 )
    {
        QDialog::accept();
    }
    else
    {
        QDialog::reject();
    }
}

void LCNInfoDlg::clickUpdate()
{
    int ret = 0;
    BIN binLCN = {0,0};
    BIN binNewLCN = {0,0};
    JS_LICENSE_INFO sInfo;

    QString strEmail = berApplet->settingsMgr()->getEmail();
    QString strLicense = berApplet->settingsMgr()->getLicense();

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( strLicense.length() <= 0 )
    {
        berApplet->warningBox( tr( "There is no current license" ), this );
        return;
    }

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binLCN );

    if( JS_LCN_ParseBIN( &binLCN, &sInfo ) == 0 )
    {
        ret = updateLCN( sInfo.sSID, sInfo.sKey, &binNewLCN );
        if( ret != 0 )
        {
            goto end;
        }

        berApplet->settingsMgr()->setEmail( sInfo.sUser );
        berApplet->settingsMgr()->setLicense( getHexString( &binNewLCN ));
        ret = 0;
    }
    else
    {
        ret = -1;
        goto end;
    }

end :
    JS_BIN_reset( &binLCN );
    JS_BIN_reset( &binNewLCN );

    if( ret == 0 )
    {
        QDialog::accept();
    }
    else
    {
        QDialog::reject();
    }
}

void LCNInfoDlg::checkUseFile()
{
    bool bVal = mUseFileCheck->isChecked();

    if( bVal )
    {
        mGetBtn->setText( "Find" );
    }
    else
    {
        mGetBtn->setText( "Get" );
    }

    mEmailText->setEnabled( !bVal );
    mKeyText->setEnabled( !bVal );
}
