/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDateTime>
#include <QSysInfo>
#include <QDesktopServices>

#include "lcn_info_dlg.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"

#include "js_license.h"
#include "js_http.h"
#include "js_cc.h"
#include "js_error.h"

LCNInfoDlg::LCNInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mLCNRequestBtn, SIGNAL(clicked()), this, SLOT(clickLCNRequest()));
    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(clickGet()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(clickUpdate()));
    connect( mRemoveBtn, SIGNAL(clicked()), this, SLOT(clickRemove()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mUseFileCheck, SIGNAL(clicked()), this, SLOT(checkUseFile()));
    connect( mStopMessageCheck, SIGNAL(clicked()), this, SLOT(checkStopMessage()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mLicenseTab->layout()->setSpacing(5);
    mLicenseTab->layout()->setMargin(5);
    mMessageTab->layout()->setSpacing(5);
    mMessageTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mLCNRequestBtn->setDefault(true);
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

    return JS_LCN_HOST_URL;
}

void LCNInfoDlg::initialize()
{
    int ret = 0;

    mUpdateBtn->hide();

    JS_LICENSE_INFO sLicenseInfo = berApplet->LicenseInfo();
    QString strEmail = berApplet->settingsMgr()->getEmail();
    SID_ = GetSystemID();

    mEmailText->setText( strEmail );

    if( sLicenseInfo.nVersion > 0 )
    {
        mCurEmailText->setText( sLicenseInfo.sUser );
        QDateTime issueTime = QDateTime::fromTime_t( JS_LCN_getUnixTimeFromUTC( sLicenseInfo.sIssued ) );
        QDateTime expireTime = QDateTime::fromTime_t( JS_LCN_getUnixTimeFromUTC( sLicenseInfo.sExpire ) );

        mCurIssueDateText->setText( issueTime.toString( "yyyy-MM-dd HH:mm:ss") );
        mCurExpireDateText->setText( expireTime.toString( "yyyy-MM-dd HH:mm:ss") );
    }

    if( berApplet->isLicense() )
    {
        ret = JS_LCN_IsValid( &sLicenseInfo, strEmail.toStdString().c_str(), JS_LCN_PRODUCT_BEREDITOR_NAME, SID_.toStdString().c_str(), time(NULL) );
        if( ret == JSR_VALID )
        {
            mCurGroup->setEnabled( true );
            mUpdateBtn->show();
            mRemoveBtn->hide();
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
        QString strMsg = tr( "This BerEditor is unlicensed version" );
        QString strAppend;

        if( sLicenseInfo.nVersion > 0 )
        {
            time_t exp_t = JS_LCN_getUnixTimeFromUTC( sLicenseInfo.sExpire );
            QDateTime expDate;
            expDate.setTime_t( exp_t );
            expDate.toString( "yyyy-MM-dd");
            strAppend = tr( "[Expired:%1]").arg( expDate.toString( "yyyy-MM-dd") );

            mCurEmailText->setStyleSheet( "color: grey;" );
            mCurIssueDateText->setStyleSheet( "color: grey;" );
            mCurExpireDateText->setStyleSheet( "color: grey;" );
        }
        else
        {
            strAppend = tr( "[No license]" );
        }

        strMsg += "\n";
        strMsg += strAppend;
        mMessageLabel->setText( strMsg );

        mCurGroup->setEnabled( false );
        time_t tLastTime = berApplet->settingsMgr()->getStopMessage();
        if( tLastTime > 0 ) mStopMessageCheck->setChecked(true);
    }

    mUpdateBtn->setEnabled( mCurGroup->isEnabled() );
//    mUseFileCheck->click();
    tabWidget->setCurrentIndex(0);
    mCloseBtn->setDefault(true);
}

void LCNInfoDlg::settingsLCN( const QString strUser, const BIN *pLCN )
{
    BIN binEncLCN = {0,0};

    JS_LCN_enc( strUser.toStdString().c_str(), pLCN, &binEncLCN );
    berApplet->settingsMgr()->setEmail( strUser );
    berApplet->settingsMgr()->setLicense( getHexString( &binEncLCN ));

    JS_BIN_reset( &binEncLCN );
}

int LCNInfoDlg::getLCN( const QString& strEmail, const QString& strKey, BIN *pLCN, QString& strError )
{
    int ret = 0;
    int status = 0;
    QString strURL;

    char *pRsp = NULL;
    JCC_NameVal sNameVal;

    QString strProduct = berApplet->getBrand();
    QSysInfo sysInfo;
    QString strInfo = QString( "%1_%2_%3_%4")
                          .arg( sysInfo.prettyProductName())
                          .arg( sysInfo.currentCpuArchitecture())
                          .arg( sysInfo.productType() )
                          .arg( sysInfo.productVersion());

    memset( &sNameVal, 0x00, sizeof(sNameVal));
    strProduct.remove( "Lite" );

    strURL = getLicenseURI();
    strURL += JS_LCN_PATH;

    QString strBody = QString( "email=%1&key=%2&product=%3&sid=%4&sysinfo=%5")
                          .arg( strEmail.simplified() )
                          .arg( strKey.simplified() )
                          .arg(strProduct).arg( SID_.simplified() )
                          .arg( strInfo.simplified() );
#ifdef QT_DEBUG
    berApplet->log( QString( "Body: %1" ).arg( strBody ));
#endif

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
        strError = QString( "[STATUS Error:%1]" ).arg( status );
        ret = JSR_HTTP_STATUS_FAIL;
        goto end;
    }

#ifdef QT_DEBUG
    berApplet->log( QString( "Rsp : %1").arg( pRsp ));
#endif

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue && strcasecmp( sNameVal.pName, "LICENSE") == 0 )
    {
        int nType = -1;
        JS_BIN_decodePEM( sNameVal.pValue, &nType, pLCN );
    }
    else
    {
        berApplet->elog( QString("HTTP Rsp Name: %1 Value: %2").arg( sNameVal.pName ).arg( sNameVal.pValue ));
        strError = QString( "[%1:%2]" ).arg( sNameVal.pName ).arg( sNameVal.pValue );
        ret = JSR_HTTP_BODY_ERROR;
        goto end;
    }

end :
    if( pRsp ) JS_free( pRsp );
    JS_UTIL_resetNameVal( &sNameVal );

    return ret;
}

int LCNInfoDlg::updateLCN( const QString strEmail, const QString strKey, BIN *pLCN, QString& strError )
{
    int ret = 0;
    int status = 0;
    QString strURL;
    char *pRsp = NULL;
    JCC_NameVal sNameVal;
    QString strProduct = berApplet->getBrand();
    QSysInfo sysInfo;
    QString strInfo = QString( "%1_%2_%3_%4")
                          .arg( sysInfo.prettyProductName())
                          .arg( sysInfo.currentCpuArchitecture())
                          .arg( sysInfo.productType() )
                          .arg( sysInfo.productVersion());


#ifndef _USE_LCN_SRV
    berApplet->warningBox( tr( "This service is not yet supported." ), this );
    return -1;
#endif

    memset( &sNameVal, 0x00, sizeof(sNameVal));
    strProduct.remove( "Lite" );

    strURL = getLicenseURI();
    strURL += JS_LCN_UPDATE_PATH;

    QString strBody = QString( "email=%1&key=%2&product=%3&sid=%4&sysinfo=%5")
                          .arg( strEmail.simplified() )
                          .arg( strKey.simplified() )
                          .arg(strProduct).arg( SID_.simplified() )
                          .arg( strInfo.simplified() );

#ifdef QT_DEBUG
    berApplet->log( QString( "Body: %1" ).arg( strBody ));
#endif

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
        strError = QString( "[STATUS Error:%1]" ).arg( status );
        ret = JSR_HTTP_STATUS_FAIL;
        goto end;
    }

#ifdef QT_DEBUG
    berApplet->log( QString( "Rsp : %1").arg( pRsp ));
#endif

    JS_CC_decodeNameVal( pRsp, &sNameVal );

    if( sNameVal.pValue && strcasecmp( sNameVal.pName, "LICENSE") == 0 )
    {
        int nType = -1;
        JS_BIN_decodePEM( sNameVal.pValue, &nType, pLCN );
    }
    else
    {
        berApplet->elog( QString("HTTP Rsp Name: %1 Value: %2").arg( sNameVal.pName ).arg( sNameVal.pValue ));
        strError = QString( "[%1:%2]" ).arg( sNameVal.pName ).arg( sNameVal.pValue );
        ret = JSR_HTTP_BODY_ERROR;
        goto end;
    }

end :
    if( pRsp ) JS_free( pRsp );
    JS_UTIL_resetNameVal( &sNameVal );

    return ret;
}

void LCNInfoDlg::clickLCNRequest()
{
    QString strURL = getLicenseURI();
    strURL += "/user_reg.php";

    QDesktopServices::openUrl(QUrl(strURL));
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
        QString strFile = findFile( this, JS_FILE_TYPE_LCN, berApplet->curPath() );
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
            mEmailText->setFocus();
            return;
        }

        if( strKey.length() < 1 )
        {
            berApplet->warningBox( tr("Please enter a license key"), this );
            mKeyText->setFocus();
            return;
        }

        ret = getLCN( strEmail, strKey, &binLCN, strErr );

        if( ret != 0 )
        {
            strErr = tr( "failed to get license %1 : %2").arg( ret ).arg( strErr );
            berApplet->warnLog( strErr, this );
            goto end;
        }
    }

    memset( &sInfo, 0x00, sizeof(sInfo));

    ret = JS_LCN_ParseBIN( &binLCN, &sInfo );
    if( ret != 0 )
    {
        strErr = tr( "failed to parse license [%1]").arg( ret );
        berApplet->warnLog( strErr, this );
        goto end;
    }

    ret = JS_LCN_IsValid( &sInfo, sInfo.sUser, JS_LCN_PRODUCT_BEREDITOR_NAME, SID_.toStdString().c_str(), time(NULL) );
    if( ret != JSR_VALID )
    {
        strErr = tr("The license is not valid:%1").arg(ret);
        berApplet->warnLog( strErr, this );
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

    settingsLCN( QString( sInfo.sUser ), &binLCN );
    ret = 0;

end :
    JS_BIN_reset( &binLCN );

    if( ret == 0 )
    {
        berApplet->settingsMgr()->setRunTime(0);

        if( berApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            berApplet->restartApp();

        QDialog::accept();
    }
}

void LCNInfoDlg::clickUpdate()
{
    int ret = 0;
    BIN binLCN = {0,0};
    BIN binEncLCN = {0,0};
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

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binEncLCN );
    if( binEncLCN.nLen > 0 ) JS_LCN_dec( strEmail.toStdString().c_str(), &binEncLCN, &binLCN );

    if( JS_LCN_ParseBIN( &binLCN, &sInfo ) == 0 )
    {
        ret = updateLCN( sInfo.sUser, sInfo.sAuthKey, &binNewLCN, strErr );
        if( ret != 0 )
        {
            strErr = tr( "failed to renew license %1 : %2").arg( ret ).arg( strErr );
            berApplet->warnLog( strErr, this );
            goto end;
        }

        if( berApplet->isLicense() )
        {
            JS_LICENSE_INFO sLicenseInfo = berApplet->LicenseInfo();

            if( memcmp( sLicenseInfo.sExpire, sInfo.sExpire, sizeof(sLicenseInfo.sExpire) ) > 0 )
            {
                strErr = tr( "Your current license has a longer usage period." );
                berApplet->warnLog( strErr, this );
                ret = -1;
                goto end;
            }
        }

        settingsLCN( QString(sInfo.sUser), &binNewLCN );
        ret = 0;
    }
    else
    {
        ret = JSR_LCN_ERR_INVALID_INPUT;
        berApplet->warnLog( tr( "License is invalid : %1" ).arg(ret), this );
        goto end;
    }

end :
    JS_BIN_reset( &binLCN );
    JS_BIN_reset( &binEncLCN );
    JS_BIN_reset( &binNewLCN );


    if( ret == 0 )
    {
        if( berApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            berApplet->restartApp();

        QDialog::accept();
    }
}

void LCNInfoDlg::clickRemove()
{
    QString strMsg = tr( "Are you sure you want to remove invalid license information?");

    bool bVal = berApplet->yesOrNoBox( strMsg, this );
    if( bVal == false ) return;

    berApplet->settingsMgr()->removeSet( "Misc", "email" );
    berApplet->settingsMgr()->removeSet( "Misc", "license" );
    berApplet->messageBox( tr( "Remove invalid license settings" ), this );
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
