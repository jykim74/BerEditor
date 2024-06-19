/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>
#include "settings_mgr.h"

namespace  {
const char *kBehaviorGroup = "Behavior";
const char *kShowPartOnly = "showPartOnly";
const char *kOIDConfigPath = "OIDConfigPath";
const char *kUseLogTab = "useLogTab";
const char *kDefaultHash = "defaultHash";
const char *kFileReadSize = "fileReadSize";
const char *kFontFamily = "fontFamily";
const char *kMisc = "Misc";
const char *kEmail = "email";
const char *kLicense = "license";
const char *kStopMessage = "stopMessage";
const char *kTrustedCAPath = "trustedCAPath";
const char *kCertPath = "certPath";
const char *kHexAreaWidth = "hexAreaWidth";
}

SettingsMgr::SettingsMgr(QObject *parent) : QObject(parent)
{
    initialize();
}

void SettingsMgr::initialize()
{
    getDefaultHash();
    getFileReadSize();
    getTrustedCAPath();
    getCertPath();
    getHexAreaWidth();
}

void SettingsMgr::removeSet( const QString& group, const QString& name )
{
    QSettings settings;

    settings.beginGroup(group);
    settings.remove( name );
    settings.endGroup();
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

void SettingsMgr::setUseLogTab( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kUseLogTab, bVal );
    settings.endGroup();
}

bool SettingsMgr::getUseLogTab()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kUseLogTab, false).toBool();
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
    file_read_size_ = sets.value( kFileReadSize, 10240 ).toInt();
    sets.endGroup();

    return file_read_size_;
}

void SettingsMgr::setFontFamily( const QString& strFamily )
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFontFamily, strFamily );
    sets.endGroup();
}

QString SettingsMgr::getFontFamily()
{
    QSettings sets;

#ifdef Q_OS_MAC
    QString strDefault = "Monaco";
#else
#ifdef Q_OS_LINUX
    QString strDefault = "Monospace";
#else
    QString strDefault = "Consolas";
#endif
#endif

    sets.beginGroup( kBehaviorGroup );
    QString strFamily = sets.value( kFontFamily, strDefault ).toString();
    sets.endGroup();

    return strFamily;
}

void SettingsMgr::setEmail( const QString strEmail )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kEmail, strEmail );
    sets.endGroup();
}

QString SettingsMgr::getEmail()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strEmail = sets.value( kEmail, "" ).toString();
    sets.endGroup();

    return strEmail;
}

void SettingsMgr::setLicense( const QString strLicense )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kLicense, strLicense );
    sets.endGroup();
}

QString SettingsMgr::getLicense()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strLicense = sets.value( kLicense, "" ).toString();
    sets.endGroup();

    return strLicense;
}

void SettingsMgr::setStopMessage( time_t tLastTime )
{
    QSettings sets;
    qint64 uLastTime = tLastTime;

    sets.beginGroup( kMisc );
    sets.setValue( kStopMessage, uLastTime );
    sets.endGroup();
}

time_t SettingsMgr::getStopMessage()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    time_t tLastTime = sets.value( kStopMessage, -1 ).toInt();
    sets.endGroup();

    return tLastTime;
}

void SettingsMgr::setTrustedCAPath( const QString strPath )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kTrustedCAPath, strPath );
    sets.endGroup();

    trusted_ca_path_ = strPath;
}

QString SettingsMgr::getTrustedCAPath()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    trusted_ca_path_ = sets.value( kTrustedCAPath, "trustedCA" ).toString();
    sets.endGroup();

    return trusted_ca_path_;
}

void SettingsMgr::setCertPath( const QString strPath )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kCertPath, strPath );
    sets.endGroup();

    cert_path_ = strPath;
}

QString SettingsMgr::getCertPath()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    cert_path_ = sets.value( kCertPath, "JSPKI" ).toString();
    sets.endGroup();

    return cert_path_;
}

void SettingsMgr::setHexAreaWidth( int width )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kHexAreaWidth, width );
    sets.endGroup();

    hex_area_width_ = width;
}

int SettingsMgr::getHexAreaWidth()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    hex_area_width_ = sets.value( kHexAreaWidth, -1 ).toInt();
    sets.endGroup();

    return hex_area_width_;
}
