#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "ber_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"
#include "common.h"
#include "mainwindow.h"

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangComboBox->addItems(I18NHelper::getInstance()->getLanguages());

    connect( mOkBtn, SIGNAL(clicked()), this, SLOT(onOkBtnClicked()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(onCancelBtnClicked()));
    connect( mFindOIDConfig, SIGNAL(clicked()), this, SLOT(findOIDConfig()));

    mTabWidget->setCurrentIndex(0);
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    mgr->setShowPartOnly( mCheckShowPartOnly->checkState() == Qt::Checked );

    mgr->setShowLogTab( mShowLogTabCheck->checkState() == Qt::Checked );
    berApplet->mainWindow()->logView( mShowLogTabCheck->checkState() == Qt::Checked );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckBoxLatestVersion->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    bool language_changed = false;

    if( mLangComboBox->currentIndex() != I18NHelper::getInstance()->preferredLanguage() )
    {
        language_changed = true;
        I18NHelper::getInstance()->setPreferredLanguage(mLangComboBox->currentIndex());
    }

    if( language_changed && berApplet->yesOrNoBox(tr("You have changed language. Restart to apply it?"), this, true))
        berApplet->restartApp();

    mgr->setOIDConfigPath( mOIDConfigPathText->text() );

    mgr->setShowLogTab( mShowLogTabCheck->checkState() == Qt::Checked );
    berApplet->mainWindow()->logView( mShowLogTabCheck->checkState() == Qt::Checked );
}

void SettingsDlg::onOkBtnClicked()
{
    updateSettings();
    accept();
}

void SettingsDlg::onCancelBtnClicked()
{
    reject();
}

void SettingsDlg::findOIDConfig()
{
    QString strPath = QDir::currentPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CFG, strPath );

    if( fileName.length() > 0 ) mOIDConfigPathText->setText( fileName );
}

void SettingsDlg::closeEvent(QCloseEvent *event)
{
    event->ignore();
    hide();
}

void SettingsDlg::showEvent(QShowEvent *event)
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    Qt::CheckState state;

    state = mgr->showPartOnly() ? Qt::Checked : Qt::Unchecked;
    mCheckShowPartOnly->setCheckState(state);

    mOIDConfigPathText->setText( mgr->OIDConfigPath() );

    state = mgr->showLogTab() ? Qt::Checked : Qt::Unchecked;
    mShowLogTabCheck->setCheckState(state);

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckBoxLatestVersion->setCheckState(state);
    }
#else
    mCheckBoxLatestVersion->hide();
#endif

    mLangComboBox->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());

    QDialog::showEvent(event);
}
