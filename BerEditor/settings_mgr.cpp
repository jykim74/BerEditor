#include <QSettings>
#include "settings_mgr.h"

namespace  {
const char *kBehaviorGroup = "Behavior";
const char *kShowPartOnly = "showPartOnly";
const char *kOIDConfigPath = "OIDConfigPath";
const char *kShowLogTab = "showLogTab";
const char *kDefaultHash = "defaultHash";
const char *kFileReadSize = "fileReadSize";
}

SettingsMgr::SettingsMgr(QObject *parent) : QObject(parent)
{
    initialize();
}

void SettingsMgr::initialize()
{
    getDefaultHash();
    getFileReadSize();
}

void SettingsMgr::setShowPartOnly(bool val)
{
//    QSettings settings( "myapp.plist", QSettings::NativeFormat );
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kShowPartOnly, val );
    settings.endGroup();
}

bool SettingsMgr::showPartOnly()
{
//    QSettings settings( "myapp.plist", QSettings::NativeFormat );
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value(kShowPartOnly, false).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setOIDConfigPath( const QString& strPath )
{
    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOIDConfigPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::OIDConfigPath()
{
    QSettings settings;
    QString strPath;

    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kOIDConfigPath, "oid.cfg" ).toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setShowLogTab( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kShowLogTab, bVal );
    settings.endGroup();
}

bool SettingsMgr::showLogTab()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kShowLogTab, false).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setDefaultHash( const QString& strHash )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kDefaultHash, strHash );
    sets.endGroup();

    default_hash_ = strHash;
}

QString SettingsMgr::getDefaultHash()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    default_hash_ = sets.value( kDefaultHash, "SHA256" ).toString();
    sets.endGroup();

    return default_hash_;
}

void SettingsMgr::setFileReadSize( int size )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFileReadSize, size );
    sets.endGroup();

    file_read_size_ = size;
}

int SettingsMgr::getFileReadSize()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    file_read_size_ = sets.value( kFileReadSize, 1024 ).toInt();
    sets.endGroup();

    return file_read_size_;
}
