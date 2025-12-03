/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    initUI();

    mLangComboBox->addItems(I18NHelper::getInstance()->getLanguages());

    connect( mOkBtn, SIGNAL(clicked()), this, SLOT(onOkBtnClicked()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(onCancelBtnClicked()));
    connect( mFindOIDConfig, SIGNAL(clicked()), this, SLOT(findOIDConfig()));
    connect( mFindCertPathBtn, SIGNAL(clicked()), this, SLOT(findCertPath()));
    connect( mRestoreDefaultsBtn, SIGNAL(clicked()), this, SLOT(clickRestoreDefaults()));

    initialize();

    mTabWidget->setCurrentIndex(0);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mBasicTab->layout()->setSpacing(5);
    mAdvancedTab->layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::initUI()
{
    const QStringList sHexWidthList = { "", "8", "16", "32", "64", "80" };

    QIntValidator *intVal = new QIntValidator( 0, 999999 );
    mFileReadSizeText->setValidator( intVal );
    mHexAreaWidthCombo->addItems( sHexWidthList );

    mPriEncMethodCombo->addItems( kPBEList );
}

void SettingsDlg::initialize()
{
    if( berApplet->isLicense() == false )
    {
        mDefaultHashGroup->setEnabled( false );
        mCheckShowTTLVSelOnly->setEnabled( false );
        mFileReadSizeGroup->setEnabled( false );
        mUseLogTabCheck->setEnabled( false );
        mCertPathGroup->setEnabled( false );
        mSupportKeyPairChangeCheck->setEnabled( false );
        mUseCertManCheck->setEnabled( false );
        mPriEncGroup->setEnabled( false );
    }

    initFontFamily();
}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    mgr->setShowBERSelOnly( mCheckShowBERSelOnly->checkState() == Qt::Checked );
    mgr->setAutoExpand( mAutoExpandCheck->checkState() == Qt::Checked );

    if( berApplet->isLicense() )
    {
        mgr->setShowTTLVSelOnly( mCheckShowTTLVSelOnly->checkState() == Qt::Checked );

        mgr->setUseLogTab( mUseLogTabCheck->checkState() == Qt::Checked );
        berApplet->mainWindow()->useLog( mUseLogTabCheck->checkState() == Qt::Checked );

        mgr->setUseCertMan( mUseCertManCheck->checkState() == Qt::Checked );
    }

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckBoxLatestVersion->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    if( berApplet->isLicense() == true )
    {
        mgr->setDefaultHash( mDefaultHashCombo->currentText() );
        mgr->setFileReadSize( mFileReadSizeText->text().toInt() );
        mgr->setCertPath( mCertPathText->text() );
        mgr->makeCertPath();
        mgr->setSupportKeyPairChagne( mSupportKeyPairChangeCheck->checkState() == Qt::Checked );
        mgr->setPriEncMethod( mPriEncMethodCombo->currentText() );
    }

    bool language_changed = false;

    if( mLangComboBox->currentIndex() != I18NHelper::getInstance()->preferredLanguage() )
    {
        language_changed = true;
        I18NHelper::getInstance()->setPreferredLanguage(mLangComboBox->currentIndex());
    }

    if( language_changed && berApplet->yesOrNoBox(tr("You have changed language. Restart to apply it?"), this, true))
        berApplet->restartApp();

    mgr->setOIDConfigPath( mOIDConfigPathText->text() );

    mgr->setUseLogTab( mUseLogTabCheck->checkState() == Qt::Checked );
    berApplet->mainWindow()->useLog( mUseLogTabCheck->checkState() == Qt::Checked );

    QString strFont = mFontFamilyCombo->currentText();
    if( strFont == "Lantinghei TC" )
    {
        berApplet->warningBox( tr( "This font(%1) is not available" ).arg(strFont), this );
    }
    else
    {
        mgr->setFontFamily( mFontFamilyCombo->currentText());
    }

    mgr->setHexAreaWidth( mHexAreaWidthCombo->currentText().toInt());
}

void SettingsDlg::clickRestoreDefaults()
{
    SettingsMgr *mgr = berApplet->settingsMgr();

    QString strMsg = tr( "Are you sure you want to clear all the saved settings?" );

    bool bVal = berApplet->yesOrNoBox( strMsg, this, false );
    if( bVal == false ) return;

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->setAutoUpdateEnabled(true);
    }
#endif

    mgr->removeSet( "Language", "current" );
    mgr->removeSet( kBehaviorGroup, kShowBERSelOnly );
    mgr->removeSet( kBehaviorGroup, kShowTTLVSelOnly );
    mgr->removeSet( kBehaviorGroup, kUseCertMan );
    mgr->removeSet( kBehaviorGroup, kAutoExpand );
    mgr->removeSet( kBehaviorGroup, kOIDConfigPath );
    mgr->removeSet( kBehaviorGroup, kUseLogTab );
    mgr->removeSet( kBehaviorGroup, kDefaultHash );
    mgr->removeSet( kBehaviorGroup, kFileReadSize );
    mgr->removeSet( kBehaviorGroup, kFontFamily );
    mgr->removeSet( kBehaviorGroup, kHexAreaWidth );
    mgr->removeSet( kBehaviorGroup, kSupportKeyPairChange );
    mgr->removeSet( kBehaviorGroup, kCertPath );
    mgr->removeSet( kBehaviorGroup, kPriEncMethod );

    if( berApplet->yesOrNoBox(tr("Restored to default settings. Restart to apply it?"), this, true))
        berApplet->restartApp();

    close();
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
    QString strPath = mOIDConfigPathText->text();

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CFG, strPath );

    if( fileName.length() > 0 ) mOIDConfigPathText->setText( fileName );
}

void SettingsDlg::findCertPath()
{
    QString strPath = mCertPathText->text();
    QString folderName = berApplet->findFolder( this, strPath, false );

    if( folderName.length() > 0 )
    {
        folderName += "/";
        folderName += "JSPKI";

        mCertPathText->setText( folderName );
    }
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

    state = mgr->getShowBERSelOnly() ? Qt::Checked : Qt::Unchecked;
    mCheckShowBERSelOnly->setCheckState(state);

    state = mgr->getAutoExpand() ? Qt::Checked : Qt::Unchecked;
    mAutoExpandCheck->setCheckState( state );

    mOIDConfigPathText->setText( mgr->OIDConfigPath() );

    if( berApplet->isLicense() )
    {
        state = mgr->getShowTTLVSelOnly() ? Qt::Checked : Qt::Unchecked;
        mCheckShowTTLVSelOnly->setCheckState(state);

        state = mgr->getUseCertMan() ? Qt::Checked : Qt::Unchecked;
        mUseCertManCheck->setCheckState( state );

        state = mgr->getUseLogTab() ? Qt::Checked : Qt::Unchecked;
        mUseLogTabCheck->setCheckState(state);

        state = mgr->getSupportKeyPairChange() ? Qt::Checked : Qt::Unchecked;
        mSupportKeyPairChangeCheck->setCheckState(state);
    }

    mFileReadSizeText->setText( QString("%1").arg(mgr->getFileReadSize()));

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckBoxLatestVersion->setCheckState(state);
    }
#else
    mCheckBoxLatestVersion->hide();
#endif

    mDefaultHashCombo->addItems( kHashList );
    mDefaultHashCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );

    mCertPathText->setText( berApplet->settingsMgr()->getCertPath() );

    mLangComboBox->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());
    mFontFamilyCombo->setCurrentText( mgr->getFontFamily() );
    mHexAreaWidthCombo->setCurrentText( QString( "%1" ).arg( berApplet->settingsMgr()->getHexAreaWidth()));
    mPriEncMethodCombo->setCurrentText( mgr->getPriEncMethod() );

    QDialog::showEvent(event);
}

void SettingsDlg::initFontFamily()
{
    SettingsMgr *mgr = berApplet->settingsMgr();
/*
    QFontDatabase fontDB;
    QStringList fontList = fontDB.families();
    mFontFamilyCombo->addItems( fontList );
*/
}
