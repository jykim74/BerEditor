/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QtGlobal>

#include <QtWidgets>
#include <QApplication>
#include <QMessageBox>
#include <QMainWindow>


#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "data_converter_dlg.h"
#include "gen_hash_dlg.h"
#include "gen_mac_dlg.h"
#include "oid_info_dlg.h"
#include "enc_dec_dlg.h"
#include "sign_verify_dlg.h"
#include "pub_enc_dec_dlg.h"
#include "gen_otp_dlg.h"
#include "edit_value_dlg.h"
#include "get_uri_dlg.h"
#include "cavp_dlg.h"

#include "auto_update_service.h"
#include "about_dlg.h"
#include "common.h"
#include "js_net.h"
#include "js_error.h"
#include "lcn_info_dlg.h"

BerApplet *berApplet;

BerApplet::BerApplet(QObject *parent) : QObject(parent)
{
    main_win_ = nullptr;
    settings_mgr_ = new SettingsMgr;

#ifdef JS_PRO
    is_pro_ = true;
#else
    is_pro_ = false;
#endif

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif

    is_license_ = false;
    memset( &license_info_, 0x00, sizeof(license_info_));
}

BerApplet::~BerApplet()
{
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif

    if( main_win_ != nullptr ) delete main_win_;
    if( settings_mgr_ != nullptr ) delete settings_mgr_;
}

void BerApplet::setCmd(const QString cmd)
{
    cmd_ = cmd;
}

QString BerApplet::getBERPath()
{
    QString strPath = QDir::currentPath();

    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    strPath = settings.value( "berPath", "" ).toString();
    settings.endGroup();

    return strPath;
}

void BerApplet::setBERPath( const QString strPath )
{
    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    settings.setValue( "berPath", strPath );
    settings.endGroup();
}

void BerApplet::start()
{    
    checkLicense();

    main_win_ = new MainWindow;
    main_win_->show();

    QString strOIDPath = settings_mgr_->OIDConfigPath();

    setOIDList( strOIDPath );

    if( isLicense() )
    {
        main_win_->useLog( settings_mgr_->getUseLogTab() );
        settings_mgr_->makeCertPath();
    }
    else
    {
        info( "The BerEditor is not licensed" );
        time_t tLastTime = berApplet->settings_mgr_->getStopMessage();
        if( tLastTime > 0 )
        {
            time_t now_t = time(NULL);
            if( now_t > ( tLastTime + 7 * 86400 ) )
            {
                berApplet->settings_mgr_->setStopMessage( now_t );
                LCNInfoDlg lcnInfo;
                lcnInfo.setCurTab(1);
                lcnInfo.exec();
            }
        }
        else
        {
            LCNInfoDlg lcnInfo;
            lcnInfo.setCurTab(1);
            lcnInfo.exec();
        }
    }

    QString strVersion = STRINGIZE(BER_EDITOR_VERSION);
    logLine();
    log( QString( "== Start BerEditor Version: %1" ).arg( strVersion ));
    logLine();
}

QString BerApplet::curFilePath( const QString strPath )
{
    if( strPath.length() > 1 ) return strPath;

    if( cur_file_.length() < 1 )
        return QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);

    return cur_file_;
}

QString BerApplet::curPath( const QString strPath )
{
    if( strPath.length() > 1 ) return strPath;

    if( cur_file_.length() < 1 )
        return QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);

    QFileInfo file;
    file.setFile( cur_file_ );
    QDir folder = file.dir();

    return folder.path();
}

int BerApplet::decodeData( const BIN *pData, const QString strPath )
{
    return main_win_->decodeData( pData, strPath );
}

int BerApplet::decodeTitle( const BIN *pData, const QString strTitle )
{
    return main_win_->decodeTitle( pData, strTitle );
}

int BerApplet::decodeTTLV( const BIN *pData )
{
    return main_win_->decodeTTLV( pData );
}

const BIN& BerApplet::getBER()
{
    return main_win_->berModel()->getBER();
}

const BIN& BerApplet::getTTLV()
{
    return main_win_->ttlvModel()->getTTLV();
}

int BerApplet::checkLicense()
{
    int ret = 0;

    is_license_ = false;


    BIN binLCN = {0,0};
    BIN binEncLCN = {0,0};

    QString strEmail = settings_mgr_->getEmail();
    QString strLicense = settings_mgr_->getLicense();
    time_t run_t = settings_mgr_->getRunTime();
    time_t now_t = time(NULL);

    QString strSID = GetSystemID();

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binEncLCN );

    if( binEncLCN.nLen > 0 )
        JS_LCN_dec( strEmail.toStdString().c_str(), &binEncLCN, &binLCN );
    else
        goto end;

    ret = JS_LCN_ParseBIN( &binLCN, &license_info_ );
    if( ret != 0 ) goto end;

    if( run_t > 0 )
    {
        if( now_t < ( run_t - 86400 ) ) // 하루 이상으로 돌아간 경우
        {
            time_t ntp_t = JS_NET_clientNTP( JS_NTP_SERVER, JS_NTP_PORT, 2 );
            if( ntp_t <= 0 ) goto end;

            now_t = ntp_t;
        }
    }

    ret = JS_LCN_IsValid( &license_info_, strEmail.toStdString().c_str(), JS_LCN_PRODUCT_BEREDITOR_NAME, strSID.toStdString().c_str(), now_t );

    if( ret == JSR_VALID )
    {
        is_license_ = true;
        settings_mgr_->setRunTime( now_t );
    }
    else
    {
        QString strMsg;

        if( ret == JSR_LCN_ERR_EXPIRED )
            strMsg = tr( "The license has expired" );
        else
            strMsg = tr( "The license is invalid: %1" ).arg(ret);

        berApplet->warningBox( strMsg, nullptr );
    }

end :
    JS_BIN_reset( &binLCN );
    JS_BIN_reset( &binEncLCN );
    return is_license_;
}

QString BerApplet::getBrand()
{
    return QString::fromUtf8( "BerEditor" );
}

void BerApplet::warningBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Warning);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();

    if (!parent && main_win_) {
        main_win_->showWindow();
    }
    qWarning("%s", msg.toUtf8().data());
}

void BerApplet::log( const QString strLog, QColor cr )
{
    main_win_->log( strLog, cr );
}

void BerApplet::logLine()
{
    log( QString( "====================================================================" ));
}

void BerApplet::logLine2()
{
    log( QString( "--------------------------------------------------------------------" ));
}

void BerApplet::info( const QString strLog, QColor cr )
{
    main_win_->info( strLog, cr );
}

void BerApplet::line( QColor cr )
{
#ifdef Q_OS_LINUX
    info( "====================================================================\n", cr );
#else
    info( "=================================================================================\n", cr );
#endif
}

void BerApplet::line2( QColor cr )
{
#ifdef Q_OS_LINUX
    info( "--------------------------------------------------------------------\n", cr );
#else
    info( "---------------------------------------------------------------------------------\n", cr );
#endif
}

void BerApplet::elog( const QString strLog )
{
    main_win_->elog( strLog );
}

void BerApplet::messageBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Information);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();
    qDebug("%s", msg.toUtf8().data());
}

bool BerApplet::yesOrNoBox(const QString& msg, QWidget *parent, bool default_val)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.setDefaultButton(default_val ? yes_btn: no_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}

bool BerApplet::yesOrCancelBox(const QString& msg, QWidget *parent, bool default_yes)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *cancel_btn = box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_yes ? yes_btn: cancel_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}

void BerApplet::messageLog( const QString strLog, QWidget *parent )
{
    messageBox( strLog, parent );
    log( strLog );
}

void BerApplet::warnLog( const QString strLog, QWidget *parent )
{
    warningBox( strLog, parent );
    elog( strLog );
}


QMessageBox::StandardButton
BerApplet::yesNoCancelBox(const QString& msg, QWidget *parent, QMessageBox::StandardButton default_btn)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_btn);
    box.exec();

    QAbstractButton *btn = box.clickedButton();
    if (btn == yes_btn) {
        return QMessageBox::Yes;
    } else if (btn == no_btn) {
        return QMessageBox::No;
    }

    return QMessageBox::Cancel;
}

bool BerApplet::detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val)
{
    QMessageBox msgBox(QMessageBox::Question,
                       getBrand(),
                       msg,
                       QMessageBox::Yes | QMessageBox::No,
                       parent != 0 ? parent : main_win_);
    msgBox.setDetailedText(detailed_text);
    msgBox.setButtonText(QMessageBox::Yes, tr("Yes"));
    msgBox.setButtonText(QMessageBox::No, tr("No"));
    // Turns out the layout box in the QMessageBox is a grid
    // You can force the resize using a spacer this way:
    QSpacerItem* horizontalSpacer = new QSpacerItem(400, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);
    QGridLayout* layout = (QGridLayout*)msgBox.layout();
    layout->addItem(horizontalSpacer, layout->rowCount(), 0, 1, layout->columnCount());
    msgBox.setDefaultButton(default_val ? QMessageBox::Yes : QMessageBox::No);
    return msgBox.exec() == QMessageBox::Yes;
}


void BerApplet::restartApp()
{
    if( QCoreApplication::closingDown() )
        return;

    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}

void BerApplet::exitApp( int nNum )
{
    if ( QCoreApplication::closingDown()) {
        return;
    }

    QCoreApplication::exit(nNum);
}

static const QString _getFileExt( int nType )
{
    QString strExt;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strExt = "crt";
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strExt = "crl";
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strExt = "csr";
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strExt = "key";
    }
    else if( nType == JS_FILE_TYPE_PKCS8 )
    {
        strExt = "pk8";
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strExt = "txt";
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strExt = "ber";
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strExt = "cfg";
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strExt = "pfx";
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strExt = "bin";
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strExt = "p7b";
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strExt = "json";
    }
    else if( nType == JS_FILE_TYPE_XML )
    {
        strExt = "xml";
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strExt = "lcn";
    }
    else if( nType == JS_FILE_TYPE_DH_PARAM )
    {
        strExt = "pem";
    }
    else
    {
        strExt = "pem";
    }

    return strExt;
}

static const QString _getFileFilter( int nType, QString& strFileType )
{
    QString strFilter;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strFileType = QObject::tr("Cert Files");
        strFilter = QString("%1 (*.crt *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strFileType = QObject::tr( "CRL Files" );
        strFilter = QString("%1 (*.crl *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strFileType = QObject::tr( "CSR Files" );
        strFilter = QString("%1 (*.csr *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.pk8 *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PKCS8 )
    {
        strFileType = QObject::tr("PKCS8 Files");
        strFilter = QString("%1 (*.pk8 *.p8 *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strFileType = QObject::tr("Text Files");
        strFilter = QString("%1 (*.txt *.log)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strFileType = QObject::tr("BER Files");
        strFilter = QString("%1 (*.ber *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strFileType = QObject::tr("Config Files");
        strFilter = QString("%1 (*.cfg *.ini)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strFileType = QObject::tr("PFX Files");
        strFilter = QString("%1 (*.pfx *.p12)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strFileType = QObject::tr("Binary Files");
        strFilter = QString("%1 (*.bin *.ber *.der)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strFileType = QObject::tr("PKCS7 Files");
        strFilter = QString("%1 (*.p7b *.pkcs7 *.cms *.der *.pem)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strFileType = QObject::tr("JSON Files");
        strFilter = QString("%1 (*.json *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_XML )
    {
        strFileType = QObject::tr("XML Files");
        strFilter = QString("%1 (*.xml *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strFileType = QObject::tr("License Files");
        strFilter = QString( "%1 (*.lcn *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_DH_PARAM )
    {
        strFileType = QObject::tr("DH Parameter Files");
        strFilter = QString("%1 (*.pem *.der)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY_PKCS8_PFX )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.der *.pem)").arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PKCS8 Files");
        strFilter += QString("%1 (*.pk8 *.p8)" ).arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PFX Files");
        strFilter += QString("%1 (*.pfx *.p12 *.pem)" ).arg( strFileType );
    }

    if( strFilter.length() > 0 ) strFilter += ";;";
    strFilter += QObject::tr( "All Files (*.*)" );

    return strFilter;
}


QString BerApplet::findFile( QWidget *parent, int nType, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
};

QString BerApplet::findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &strSelected,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
};


QString BerApplet::findSaveFile( QWidget *parent, int nType, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 )
    {
        QStringList nameVal = fileName.split( "." );
        if( nameVal.size() < 2 )
            fileName = QString( "%1.%2" ).arg( fileName ).arg( _getFileExt( nType ) );

        if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;
    }

    return fileName;
};

QString BerApplet::findSaveFile( QWidget *parent, const QString strFilter, const QString strPath, bool bSave )
{
    QString strCurPath = curFilePath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFileType;
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 && bSave == true ) cur_file_ = fileName;

    return fileName;
}

QString BerApplet::findFolder( QWidget *parent, const QString strPath, bool bSave )
{
    QString strCurPath = curPath( strPath );

    QFileDialog::Options options;
    options |= QFileDialog::ShowDirsOnly;
    options |= QFileDialog::DontResolveSymlinks;


    QString folderName = QFileDialog::getExistingDirectory(
        parent, QObject::tr("Open Directory"), strCurPath, options);

    if( folderName.length() > 0 && bSave == true ) cur_file_ = folderName;

    return folderName;
}

