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
#include "gen_hmac_dlg.h"
#include "oid_info_dlg.h"
#include "enc_dec_dlg.h"
#include "sign_verify_dlg.h"
#include "rsa_enc_dec_dlg.h"
#include "gen_otp_dlg.h"
#include "edit_value_dlg.h"

#include "auto_update_service.h"
#include "about_dlg.h"

BerApplet *berApplet;

BerApplet::BerApplet(QObject *parent) : QObject(parent)
{
    main_win_ = new MainWindow;
    settings_dlg_ = new SettingsDlg;
    settings_mgr_ = new SettingsMgr;
    data_encoder_dlg_ = new DataEncoderDlg;
    gen_hash_dlg_ = new GenHashDlg;
    gen_hmac_dlg_ = new GenHmacDlg;
    oid_info_dlg_ = new OIDInfoDlg;
    about_dlg_ = new AboutDlg;
    enc_dec_dlg_ = new EncDecDlg;
    sign_verify_dlg_ = new SignVerifyDlg;
    rsa_enc_dec_dlg_ = new RSAEncDecDlg;
    gen_otp_dlg_ = new GenOTPDlg;
    edit_value_dlg_ = new EditValueDlg;

    started_ = false;
    in_exit_ = false;
    about_to_quit_ = false;

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif
}

BerApplet::~BerApplet()
{
    delete main_win_;
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif
}

void BerApplet::start()
{
    main_win_->show();
}

QString BerApplet::getBrand()
{
    return QString::fromUtf8( "BerViewer" );
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
