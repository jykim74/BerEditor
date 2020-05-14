#include <QSettings>
#include "settings_mgr.h"

namespace  {
const char *kBehaviorGroup = "Behavior";
const char *kShowFullText = "showFullText";
const char *kSaveOpenFolder = "saveOpenFolder";
}

SettingsMgr::SettingsMgr(QObject *parent) : QObject(parent)
{

}

void SettingsMgr::setShowFullText(bool val)
{
//    QSettings settings( "myapp.plist", QSettings::NativeFormat );
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kShowFullText, val );
    settings.endGroup();
}

bool SettingsMgr::showFullText()
{
//    QSettings settings( "myapp.plist", QSettings::NativeFormat );
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value(kShowFullText, false).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setSaveOpenFolder( bool val )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSaveOpenFolder, val );
    settings.endGroup();
}

bool SettingsMgr::isSaveOpenFolder()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kSaveOpenFolder, false).toBool();
    settings.endGroup();

    return val;
}
