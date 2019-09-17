#include <QSettings>
#include "settings_mgr.h"

namespace  {
const char *kBehaviorGroup = "Behavior";
const char *kShowFullText = "showFullText";
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
