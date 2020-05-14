#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "ber_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangComboBox->addItems(I18NHelper::getInstance()->getLanguages());

    connect( mOkBtn, SIGNAL(clicked()), this, SLOT(onOkBtnClicked()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(onCancelBtnClicked()));
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    mgr->setShowFullText( mCheckBoxShowFullText->checkState() == Qt::Checked );
    mgr->setSaveOpenFolder( mCheckSaveOpenFolder->checkState() == Qt::Checked );

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

void SettingsDlg::closeEvent(QCloseEvent *event)
{
    event->ignore();
    hide();
}

void SettingsDlg::showEvent(QShowEvent *event)
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    Qt::CheckState state;

    state = mgr->showFullText() ? Qt::Checked : Qt::Unchecked;
    mCheckBoxShowFullText->setCheckState(state);

    state = mgr->isSaveOpenFolder() ? Qt::Checked : Qt::Unchecked;
    mCheckSaveOpenFolder->setCheckState(state);

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckBoxLatestVersion->setCheckState(state);
    }
#endif

    mLangComboBox->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());

    QDialog::showEvent(event);
}
