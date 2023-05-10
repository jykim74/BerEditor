#include <QtGlobal>

#include <QtWidgets>
#include <QApplication>
#include <QMessageBox>
#include <QMainWindow>

#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "data_encoder_dlg.h"
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

BerApplet *berApplet;

BerApplet::BerApplet(QObject *parent) : QObject(parent)
{
    settings_mgr_ = new SettingsMgr;
    cavp_dlg_ = new CAVPDlg;

#ifdef JS_PRO
    is_pro_ = true;
#else
    is_pro_ = false;
#endif

    started_ = false;
    in_exit_ = false;
    about_to_quit_ = false;

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
    delete main_win_;
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif
}

void BerApplet::setCmd(const QString cmd)
{
    cmd_ = cmd;
}

QString BerApplet::getSetPath()
{
    QString strPath = QDir::currentPath();

    QSettings settings;
    settings.beginGroup( "bereditor" );
    strPath = settings.value( "openPath", "" ).toString();
    settings.endGroup();

    return strPath;
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
        if( settings_mgr_->showLogTab() )
            main_win_->logView();
    }
    else
    {
        info( "The BerEditor is not licensed" );
    }

    QString strVersion = STRINGIZE(BER_EDITOR_VERSION);
    log( "======================================================");
    log( QString( "== Start BerEditor Version: %1" ).arg( strVersion ));
    log( "======================================================");
}

int BerApplet::checkLicense()
{
    QFile resFile( ":/bereditor_license.lcn" );
    resFile.open(QIODevice::ReadOnly);
    QByteArray data = resFile.readAll();
    resFile.close();

    char sKey[128];

    memset( sKey, 0x00, sizeof(sKey));
    memcpy( &license_info_, data.data(), data.size() );

    if( memcmp( license_info_.sProduct, "BerEditor", 9 ) != 0 )
    {
        is_license_ = false;
        return is_license_;
    }

    JS_License_DeriveKey( sKey, &license_info_ );

    QDate expireDate = QDate::fromString( license_info_.sExpire, "yyyy-MM-dd" );
    QDate nowDate = QDate::currentDate();

    if( expireDate < nowDate )
    {
        is_license_ = false;
        return is_license_;
    }

    if( memcmp( sKey, license_info_.sKey, sizeof(license_info_.sKey)) == 0 )
        is_license_ = true;
    else
        is_license_ = false;

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

void BerApplet::info( const QString strLog, QColor cr )
{
    main_win_->info( strLog, cr );
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
    if( in_exit_ || QCoreApplication::closingDown() )
        return;

    in_exit_ = true;


    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}
