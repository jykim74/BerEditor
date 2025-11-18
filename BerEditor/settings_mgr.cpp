/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QSettings>
#include <QDir>
#include "settings_mgr.h"



SettingsMgr::SettingsMgr(QObject *parent) : QObject(parent)
{
    show_part_ = false;
    default_hash_ = "";
    cert_path_ = "";
    hex_area_width_ = -1;
    support_keypair_change_ = false;
    use_certman_ = false;
    auto_expand_ = false;

    initialize();
}

void SettingsMgr::initialize()
{
    getShowPartOnly();
    getUseCertMan();
    getAutoExpand();

    getDefaultHash();
    getFileReadSize();
    getHexAreaWidth();
    getCertPath();
    getSupportKeyPairChange();

    getViewValue( VIEW_FILE );
    getViewValue( VIEW_EDIT );
    getViewValue( VIEW_TOOL );
    getViewValue( VIEW_CRYPT );
    getViewValue( VIEW_SERVICE );
    getViewValue( VIEW_PROTO );
    getViewValue( VIEW_KMIP );
    getViewValue( VIEW_HELP );

    getLinkList();
    getPriEncMethod();
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
    QSettings settings;
    show_part_ = val;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kShowPartOnly, show_part_ );
    settings.endGroup();
}

bool SettingsMgr::getShowPartOnly()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    show_part_ = settings.value(kShowPartOnly, false).toBool();
    settings.endGroup();

    return show_part_;
}

void SettingsMgr::setUseCertMan( bool val )
{
    QSettings settings;
    use_certman_ = val;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kUseCertMan, use_certman_ );
    settings.endGroup();
}

bool SettingsMgr::getUseCertMan()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    use_certman_ = settings.value(kUseCertMan, false).toBool();
    settings.endGroup();

    return use_certman_;
}

void SettingsMgr::setAutoExpand( bool val )
{
    QSettings settings;
    auto_expand_ = val;

    settings.beginGroup(kBehaviorGroup);
    settings.setValue( kAutoExpand, auto_expand_ );
    settings.endGroup();
}

bool SettingsMgr::getAutoExpand()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    auto_expand_ = settings.value(kAutoExpand, false).toBool();
    settings.endGroup();

    return auto_expand_;
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
    sets.beginGroup( kEnvMiscGroup );
    sets.setValue( kEmail, strEmail );
    sets.endGroup();
}

QString SettingsMgr::getEmail()
{
    QSettings sets;

    sets.beginGroup( kEnvMiscGroup );
    QString strEmail = sets.value( kEmail, "" ).toString();
    sets.endGroup();

    return strEmail;
}

void SettingsMgr::setLicense( const QString strLicense )
{
    QSettings sets;
    sets.beginGroup( kEnvMiscGroup );
    sets.setValue( kLicense, strLicense );
    sets.endGroup();
}

QString SettingsMgr::getLicense()
{
    QSettings sets;

    sets.beginGroup( kEnvMiscGroup );
    QString strLicense = sets.value( kLicense, "" ).toString();
    sets.endGroup();

    return strLicense;
}

void SettingsMgr::setStopMessage( time_t tLastTime )
{
    QSettings sets;
    qint64 uLastTime = tLastTime;

    sets.beginGroup( kEnvMiscGroup );
    sets.setValue( kStopMessage, uLastTime );
    sets.endGroup();
}

time_t SettingsMgr::getStopMessage()
{
    QSettings sets;

    sets.beginGroup( kEnvMiscGroup );
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

QString SettingsMgr::keyPairPath()
{
    QString strPath;

    strPath = QString( "%1/KeyPair" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::keyListPath()
{
    QString strPath;

    strPath = QString( "%1/KeyList" ).arg( cert_path_ );
    return strPath;
}

QString SettingsMgr::docPath()
{
    QString strPath;

    strPath = QString( "%1/DOC" ).arg( cert_path_ );
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

    if( dir.exists( keyPairPath() ) == false )
        dir.mkdir( keyPairPath() );

    if( dir.exists( keyListPath() ) == false )
        dir.mkdir( keyListPath() );

    if( dir.exists( docPath() ) == false )
        dir.mkdir( docPath() );
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

int SettingsMgr::viewValue( int nType )
{
    switch (nType) {
    case VIEW_FILE: return view_file_;
    case VIEW_EDIT: return view_edit_;
    case VIEW_TOOL: return view_tool_;
    case VIEW_CRYPT: return view_crypt_;
    case VIEW_SERVICE: return view_service_;
    case VIEW_PROTO: return view_proto_;
    case VIEW_KMIP: return view_kmip_;
    case VIEW_HELP: return view_help_;
    default:
        break;
    }

    return -1;
}


int SettingsMgr::getViewValue( int nType )
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
    case VIEW_SERVICE:
        ret = settings.value( kViewService, kServiceDefault ).toInt();
        view_service_ = ret;
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
        view_help_ = ret;
        break;
    default:
        break;
    }

    settings.endGroup();
    return ret;
}


void SettingsMgr::setViewValue( int nVal )
{
    QSettings settings;
    settings.beginGroup(kBehaviorGroup);

    int nType = -1;

    nType = nVal & 0xFF000000;

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
    case VIEW_SERVICE:
        settings.setValue( kViewService, nVal );
        view_service_ = nVal;
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

void SettingsMgr::clearViewValue( int nType )
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
    case VIEW_SERVICE:
        settings.remove( kViewService );
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

void SettingsMgr::setLinkList( const QString strPath )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kLinkList, strPath );
    sets.endGroup();

    link_list_ = strPath;
}

QString SettingsMgr::getLinkList()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    link_list_ = sets.value( kLinkList, "" ).toString();
    sets.endGroup();

    return link_list_;
}

void SettingsMgr::setPriEncMethod( const QString strMethod )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kPriEncMethod, strMethod );
    sets.endGroup();

    pri_enc_method_ = strMethod;
}

QString SettingsMgr::getPriEncMethod()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    pri_enc_method_ = sets.value( kPriEncMethod, "AES-128-CBC" ).toString();
    sets.endGroup();

    return pri_enc_method_;
}

void SettingsMgr::setRunTime( time_t tRun )
{
    int nTime = tRun;
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kRunTime, nTime );
    sets.endGroup();
}

time_t SettingsMgr::getRunTime()
{
    time_t tRun = 0;
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    tRun = sets.value( kRunTime, 0 ).toInt();
    sets.endGroup();

    return tRun;
}
