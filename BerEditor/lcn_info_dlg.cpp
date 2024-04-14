/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDateTime>

#include "lcn_info_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"

#include "js_license.h"
#include "js_http.h"
#include "js_cc.h"
#include "js_error.h"

const QString kLicenseURI = "http://localhost:80";

LCNInfoDlg::LCNInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(clickGet()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mUseFileCheck, SIGNAL(clicked()), this, SLOT(checkUseFile()));
    connect( mStopMessageCheck, SIGNAL(clicked()), this, SLOT(checkStopMessage()));

    initialize();
}

LCNInfoDlg::~LCNInfoDlg()
{

}

void LCNInfoDlg::setCurTab(int index)
{
    tabWidget->setCurrentIndex(index);
}

QString LCNInfoDlg::getLicenseURI()
{
    QString url_from_env = qgetenv("JS_INC_LICENSE_URI");

    if( !url_from_env.isEmpty() )
    {
        qWarning( "winsparkle: using app cast url from JS_INC_LICENSE_URI: "
                  "%s", url_from_env.toUtf8().data() );

        return url_from_env;
    }

    return kLicenseURI;
}

void LCNInfoDlg::initialize()
{
    int ret = 0;
    mUpdateBtn->setEnabled( false );
    JS_LICENSE_INFO sLicenseInfo = berApplet->LicenseInfo();

    if( berApplet->isLicense() )
    {
        QString strExt;

        QDateTime issueTime = QDateTime::fromString( sLicenseInfo.sIssued, JS_LCN_TIME_FORMAT);
        QDateTime expireTime = QDateTime::fromString( sLicenseInfo.sExpire, JS_LCN_TIME_FORMAT );

        mUpdateBtn->setEnabled(true);

        if( strExt.toUpper() == "DEMO" )
            mCurEmailText->setText( "For Demo");
        else
            mCurEmailText->setText( sLicenseInfo.sUser );

        mCurIssueDateText->setText( issueTime.toString( "yyyy-MM-dd HH:mm:ss") );
        mCurExpireDateText->setText( expireTime.toString( "yyyy-MM-dd HH:mm:ss") );

        ret = JS_LCN_IsValid( &sLicenseInfo, JS_LCN_PRODUCT_BEREDITOR_NAME, sLicenseInfo.sSID, time(NULL) );
        if( ret == JSR_VALID )
        {
            mCurGroup->setEnabled( true );
            mUpdateBtn->setEnabled( true );
        }
        else
        {
            mCurGroup->setEnabled( false );
        }
        
        mMessageLabel->setText( tr("This BerEditor is licensed version") );
        mStopMessageCheck->hide();
    }
    else
    {
        QString strMsg = tr( "This BerEditor is unlicensed version.\r\n" );
        QString strAppend;

        if( sLicenseInfo.nVersion > 0 )
        {
            strAppend = tr( "Expiration date: %1").arg( sLicenseInfo.sExpire );
        }
        else
        {
            strAppend = tr( "The license is not a valid license." );
        }

        strMsg += strAppend;
        mMessageLabel->setText( strMsg );

        mCurGroup->setEnabled( false );
        time_t tLastTime = berApplet->settingsMgr()->getStopMessage();
        if( tLastTime > 0 ) mStopMessageCheck->setChecked(true);
    }

    mUpdateBtn->setEnabled( mCurGroup->isEnabled() );
    mUseFileCheck->click();
    tabWidget->setCurrentIndex(0);
}

void LCNInfoDlg::settingsLCN( const QString strSID, const BIN *pLCN )
{
    BIN binEncLCN = {0,0};

    JS_LCN_enc( strSID.toStdString().c_str(), pLCN, &binEncLCN );
    berApplet->settingsMgr()->setEmail( strSID );
    berApplet->settingsMgr()->setLicense( getHexString( &binEncLCN ));

    JS_BIN_reset( &binEncLCN );
}

int LCNInfoDlg::getLCN( const QString& strEmail, const QString& strKey, BIN *pLCN )
{
    int ret = 0;
    int status = 0;
    QString strURL;

    char *pRsp = NULL;
    JCC_NameVal sNameVal;

    QString strProduct = berApplet->getBrand();
    QString strSID = GetSystemID();

    memset( &sNameVal, 0x00, sizeof(sNameVal));
    strProduct.remove( "Lite" );

    strURL = getLicenseURI();
    strURL += "/jsinc/lcn.php";

    QString strBody = QString( "email=%1&key=%2&product=%3&sid=%4")
                          .arg( strEmail )
                          .arg( strKey )
                          .arg(strProduct).arg( strSID );

    ret = JS_HTTP_requestPost2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-www-form-urlencoded",
        strBody.toStdString().c_str(),
        &status,
        &pRsp );

    if( status != JS_HTTP_STATUS_OK)
    {
        berApplet->elog( QString("HTTP get ret:%1 status: %2").arg( ret ).arg( status ));
        ret = -1;
        goto end;
    }

    berApplet->log( QString( "Rsp : %1").arg( pRsp ));

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue )
    {
        JS_BIN_decodeHex( sNameVal.pValue, pLCN );
    }

end :
    if( pRsp ) JS_free( pRsp );
    JS_UTIL_resetNameVal( &sNameVal );

    return ret;
}

int LCNInfoDlg::updateLCN( const QString strEmail, const QString strKey, BIN *pLCN )
{
    int ret = 0;
    int status = 0;
    QString strURL;
    char *pRsp = NULL;
    JCC_NameVal sNameVal;
    QString strProduct = berApplet->getBrand();
    QString strSID = GetSystemID();

#ifndef _USE_LCN_SRV
    berApplet->warningBox( tr( "This service is not yet supported." ), this );
    return -1;
#endif

    memset( &sNameVal, 0x00, sizeof(sNameVal));
    strProduct.remove( "Lite" );

    strURL = getLicenseURI();
    strURL += "/jsinc/lcn_update.php";

    QString strBody = QString( "email=%1&key=%2&product=%3&sid=%4")
                          .arg( strEmail )
                          .arg( strKey )
                          .arg(strProduct).arg( strSID );

    ret = JS_HTTP_requestPost2(
        strURL.toStdString().c_str(),
        NULL,
        NULL,
        "application/x-www-form-urlencoded",
        strBody.toStdString().c_str(),
        &status,
        &pRsp );

    if( status != JS_HTTP_STATUS_OK)
    {
        berApplet->elog( QString("HTTP get ret:%1 status: %2").arg( ret ).arg( status ));
        ret = -1;
        goto end;
    }

    if( status != JS_HTTP_STATUS_OK)
    {
        berApplet->elog( QString("HTTP get ret:%1 status: %2").arg( ret ).arg( status ));
        ret = -2;
        goto end;
    }

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue )
    {
        JS_BIN_decodeHex( sNameVal.pValue, pLCN );
    }
end :
    if( pRsp ) JS_free( pRsp );
    JS_UTIL_resetNameVal( &sNameVal );

    return ret;
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
        QString strFile = findFile( this, JS_FILE_TYPE_LCN, berApplet->curFolder() );
        if( strFile.length() < 1 ) return;
        JS_LCN_fileRead( strFile.toLocal8Bit().toStdString().c_str(), &binLCN );
    }
    else
    {
#ifndef _USE_LCN_SRV
        berApplet->warningBox( tr( "This service is not yet supported." ), this );
        return;
#endif

        QString strEmail = mEmailText->text();
        QString strKey = mKeyText->text();

        if( strEmail.length() < 1 )
        {
            berApplet->warningBox( tr("Please enter a email"), this );
            return;
        }

        if( strKey.length() < 1 )
        {
            berApplet->warningBox( tr("Please enter a license key"), this );
            return;
        }

        ret = getLCN( strEmail, strKey, &binLCN );

        if( ret != 0 )
        {
            strErr = tr( "failed to get license:%1").arg( ret );
            berApplet->elog( strErr );
            berApplet->warningBox( strErr, this );
            goto end;
        }
    }

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_LCN_ParseBIN( &binLCN, &sInfo );
    if( ret != 0 )
    {
        strErr = tr( "failed to parse license [%1]").arg( ret );
        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
        goto end;
    }

    ret = JS_LCN_IsValid( &sInfo, JS_LCN_PRODUCT_BEREDITOR_NAME, sInfo.sSID, time(NULL) );
    if( ret != JSR_VALID )
    {
        strErr = tr("The license is not valid:%1").arg(ret);

        berApplet->elog( strErr );
        berApplet->warningBox( strErr, this );
        ret = -1;
        goto end;
    }

    if( berApplet->isLicense() )
    {
        JS_LICENSE_INFO sLicenseInfo = berApplet->LicenseInfo();

        if( memcmp( sLicenseInfo.sExpire, sInfo.sExpire, sizeof(sLicenseInfo.sExpire) ) > 0 )
        {
            strErr = tr( "Your current license has a longer usage period." );
            berApplet->elog( strErr );
            berApplet->warningBox( strErr, this );
            ret = -1;
            goto end;
        }
    }

    settingsLCN( QString( sInfo.sSID), &binLCN );
    ret = 0;

end :
    JS_BIN_reset( &binLCN );

    if( ret == 0 )
    {
        if( berApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            berApplet->restartApp();

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
    QString strErr;

    QString strEmail = berApplet->settingsMgr()->getEmail();
    QString strLicense = berApplet->settingsMgr()->getLicense();

#ifndef _USE_LCN_SRV
    berApplet->warningBox( tr( "This service is not yet supported." ), this );
    return;
#endif

    memset( &sInfo, 0x00, sizeof(sInfo));

    if( strLicense.length() <= 0 )
    {
        berApplet->warningBox( tr( "There is currently no license." ), this );
        return;
    }

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binLCN );

    if( JS_LCN_ParseBIN( &binLCN, &sInfo ) == 0 )
    {
        ret = updateLCN( sInfo.sSID, sInfo.sAuthKey, &binNewLCN );
        if( ret != 0 )
        {
            strErr = tr( "failed to renew license:%1").arg( ret );
            berApplet->elog( strErr );
            berApplet->warningBox( strErr, this );
            goto end;
        }

        if( berApplet->isLicense() )
        {
            JS_LICENSE_INFO sLicenseInfo = berApplet->LicenseInfo();

            if( memcmp( sLicenseInfo.sExpire, sInfo.sExpire, sizeof(sLicenseInfo.sExpire) ) > 0 )
            {
                strErr = tr( "Your current license has a longer usage period." );
                berApplet->elog( strErr );
                berApplet->warningBox( strErr, this );
                ret = -1;
                goto end;
            }
        }

        settingsLCN( QString(sInfo.sSID), &binNewLCN );
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
    mReqGroup->setEnabled( !bVal );

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

void LCNInfoDlg::checkStopMessage()
{
    bool bVal = mStopMessageCheck->isChecked();

    if( bVal )
    {
        time_t now_t = time(NULL);
        QString strMessage = QString( "LastCheck:%1").arg( now_t );
        berApplet->settingsMgr()->setStopMessage( now_t );
    }
    else
    {
        berApplet->settingsMgr()->setStopMessage( 0 );
    }
}
