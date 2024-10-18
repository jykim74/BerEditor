/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>
#include <QDir>
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
const char *kCertPath = "certPath";
const char *kHexAreaWidth = "hexAreaWidth";
const char *kSupportKeyPairChange = "SupportKeyPairChange";
const char *kViewFile = "viewFile";
const char *kViewEdit = "viewEdit";
const char *kViewTool = "viewTool";
const char *kViewCrypt = "viewCrypt";
const char *kViewProto = "viewProto";
const char *kViewKMIP = "viewKMIP";
const char *kViewHelp = "viewHelp";
}

SettingsMgr::SettingsMgr(QObject *parent) : QObject(parent)
{
    show_part_ = false;
    default_hash_ = "";
    cert_path_ = "";
    hex_area_width_ = -1;
    support_keypair_change_ = false;

    initialize();
}

void SettingsMgr::initialize()
{
    getShowPartOnly();
    getDefaultHash();
    getFileReadSize();
    getHexAreaWidth();
    getCertPath();
    getSupportKeyPairChange();

    getViewValue( VIEW_FILE );
    getViewValue( VIEW_EDIT );
    getViewValue( VIEW_TOOL );
    getViewValue( VIEW_CRYPT );
    getViewValue( VIEW_PROTO );
    getViewValue( VIEW_KMIP );
    getViewValue( VIEW_HELP );
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
    show_part_ = val;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kShowPartOnly, show_part_ );
    settings.endGroup();
}

bool SettingsMgr::getShowPartOnly()
{
//    QSettings settings( "myapp.plist", QSettings::NativeFormat );
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    show_part_ = settings.value(kShowPartOnly, false).toBool();
    settings.endGroup();

    return show_part_;
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

QString SettingsMgr::trustCertPath()
{
    QString strPath;

    strPath = QString( "%1/Trust" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::EECertPath()
{
    QString strPath;

    strPath = QString( "%1/EE" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::otherCertPath()
{
    QString strPath;

    strPath = QString( "%1/Other" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::CACertPath()
{
    QString strPath;

    strPath = QString( "%1/CA" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::CRLPath()
{
    QString strPath;

    strPath = QString( "%1/CRL" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::tempCertPath()
{
    QString strPath;

    strPath = QString( "%1/Temp" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::keyPairPath()
{
    QString strPath;

    strPath = QString( "%1/KeyPair" ).arg( cert_path_ );
    return strPath;
}

void SettingsMgr::makeCertPath()
{
    QDir dir;

    if( dir.exists( certPath() ) == false )
        dir.mkdir( certPath() );

    if( dir.exists( EECertPath() ) == false )
        dir.mkdir( EECertPath() );

    if( dir.exists( otherCertPath() ) == false )
        dir.mkdir( otherCertPath() );

    if( dir.exists( CACertPath() ) == false )
        dir.mkdir( CACertPath() );

    if( dir.exists( CRLPath() ) == false )
        dir.mkdir( CRLPath() );

    if( dir.exists( trustCertPath() ) == false )
        dir.mkdir( trustCertPath() );

    if( dir.exists( tempCertPath() ) == false )
        dir.mkdir( tempCertPath() );

    if( dir.exists( keyPairPath() ) == false )
        dir.mkdir( keyPairPath() );
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

void SettingsMgr::setSupportKeyPairChagne( bool val )
{
    QSettings settings;
    support_keypair_change_ = val;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kSupportKeyPairChange, support_keypair_change_ );
    settings.endGroup();
}

bool SettingsMgr::getSupportKeyPairChange()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    support_keypair_change_ = settings.value(kSupportKeyPairChange, false).toBool();
    settings.endGroup();

    return support_keypair_change_;
}

int SettingsMgr::viewValue( ViewType nType )
{
    switch (nType) {
    case VIEW_FILE: return view_file_;
    case VIEW_EDIT: return view_edit_;
    case VIEW_TOOL: return view_tool_;
    case VIEW_CRYPT: return view_crypt_;
    case VIEW_PROTO: return view_proto_;
    case VIEW_KMIP: return view_kmip_;
    case VIEW_HELP: return view_help_;
    default:
        break;
    }

    return -1;
}


int SettingsMgr::getViewValue( ViewType nType )
{
    int ret = -1;
    QSettings settings;
    settings.beginGroup(kBehaviorGroup);

    switch (nType) {
    case VIEW_FILE:
        ret = settings.value( kViewFile, kFileDefault ).toInt();
        view_file_ = ret;
        break;
    case VIEW_EDIT:
        ret = settings.value( kViewEdit, kEditDefault ).toInt();
        view_edit_ = ret;
        break;
    case VIEW_TOOL:
        ret = settings.value( kViewTool, kToolDefault ).toInt();
        view_tool_ = ret;
        break;
    case VIEW_CRYPT:
        ret = settings.value( kViewCrypt, kCryptDefault ).toInt();
        view_crypt_ = ret;
        break;
    case VIEW_PROTO:
        ret = settings.value( kViewProto, kProtoDefault ).toInt();
        view_proto_ = ret;
        break;
    case VIEW_KMIP:
        ret = settings.value( kViewKMIP, kKMIPDefault ).toInt();
        view_kmip_ = ret;
        break;
    case VIEW_HELP:
        ret = settings.value( kViewHelp, kHelpDefault ).toInt();
        view_file_ = ret;
        break;
    default:
        break;
    }

    settings.endGroup();
    return ret;
}


void SettingsMgr::setViewValue( ViewType nType, int nVal )
{
    QSettings settings;
    settings.beginGroup(kBehaviorGroup);

    switch (nType) {
    case VIEW_FILE:
        settings.setValue( kViewFile, nVal );
        view_file_ = nVal;
        break;
    case VIEW_EDIT:
        settings.setValue( kViewEdit, nVal );
        view_edit_ = nVal;
        break;
    case VIEW_TOOL:
        settings.setValue( kViewTool, nVal );
        view_tool_ = nVal;
        break;
    case VIEW_CRYPT:
        settings.setValue( kViewCrypt, nVal );
        view_crypt_ = nVal;
        break;
    case VIEW_PROTO:
        settings.setValue( kViewProto, nVal );
        view_proto_ = nVal;
        break;
    case VIEW_KMIP:
        settings.setValue( kViewKMIP, nVal );
        view_kmip_ = nVal;
        break;
    case VIEW_HELP:
        settings.setValue( kViewHelp, nVal );
        view_help_ = nVal;
        break;
    default:
        break;
    }

    settings.endGroup();
}

void SettingsMgr::clearViewValue( ViewType nType )
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    switch (nType) {
    case VIEW_FILE:
        settings.remove( kViewFile );
        break;
    case VIEW_EDIT:
        settings.remove( kViewEdit );
        break;
    case VIEW_TOOL:
        settings.remove( kViewTool );
        break;
    case VIEW_CRYPT:
        settings.remove( kViewCrypt );
        break;
    case VIEW_PROTO:
        settings.remove( kViewProto );
        break;
    case VIEW_KMIP:
        settings.remove( kViewKMIP );
        break;
    case VIEW_HELP:
        settings.remove( kViewHelp );
        break;
    default:
        break;
    }

    settings.endGroup();
}
