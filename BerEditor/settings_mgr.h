/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>
#include "common.h"

namespace  {
const char *kBehaviorGroup = "Behavior";
const char *kShowPartOnly = "showPartOnly";
const char *kOIDConfigPath = "OIDConfigPath";
const char *kUseLogTab = "useLogTab";
const char *kDefaultHash = "defaultHash";
const char *kFileReadSize = "fileReadSize";
const char *kFontFamily = "fontFamily";
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
const char *kViewService = "viewService";
const char *kViewProto = "viewProto";
const char *kViewKMIP = "viewKMIP";
const char *kViewHelp = "viewHelp";
const char *kLinkList = "linkList";
const char *kRunTime = "runTime";
const char *kUseCertMan = "useCertMan";
}

class SettingsMgr : public QObject
{
    Q_OBJECT
private:

public:
    SettingsMgr(QObject *parent = nullptr);
    void removeSet( const QString& group, const QString& name );

    void setShowPartOnly( bool val );
    bool getShowPartOnly();
    bool showPartOnly() { return show_part_; };

    void setUseCertMan( bool val );
    bool getUseCertMan();
    bool useCertMan() { return use_certman_; };

    void setOIDConfigPath( const QString& strPath );
    QString OIDConfigPath();

    void setUseLogTab( bool bVal );
    bool getUseLogTab();

    void setDefaultHash( const QString& strHash );
    QString getDefaultHash();
    QString defaultHash() { return default_hash_; };

    void setFileReadSize( int size );
    int getFileReadSize();
    int fileReadSize() { return file_read_size_; };

    void setFontFamily( const QString& strFamily );
    QString getFontFamily();

    void setEmail( const QString strEmail );
    QString getEmail();

    void setLicense( const QString strLicense );
    QString getLicense();

    void setStopMessage( time_t tLastTime );
    time_t getStopMessage();

    void setCertPath( const QString strPath );
    QString getCertPath();
    QString certPath() { return cert_path_; };

    QString trustCertPath();
    QString EECertPath();
    QString otherCertPath();
    QString CACertPath();
    QString CRLPath();
    QString keyPairPath();
    QString keyListPath();
    QString docPath();

    void makeCertPath();

    void setHexAreaWidth( int width );
    int getHexAreaWidth();
    int hexAreaWidth() { return hex_area_width_; };

    void setSupportKeyPairChagne( bool val );
    bool getSupportKeyPairChange();
    bool supportKeyPairChange() { return support_keypair_change_; };

    int viewValue( int nType );
    int getViewValue( int nType );
    void setViewValue( int nVal );
    void clearViewValue( int nType );

    void setLinkList( const QString strLinkList );
    QString getLinkList();
    QString linkList() { return link_list_; };

    void setRunTime( time_t tRun );
    time_t getRunTime();

signals:

private:
    void initialize();

private:
    bool show_part_;
    QString default_hash_;
    int file_read_size_;
    QString cert_path_;
    int hex_area_width_;
    bool support_keypair_change_;
    bool use_certman_;

    int view_file_;
    int view_edit_;
    int view_tool_;
    int view_crypt_;
    int view_service_;
    int view_proto_;
    int view_kmip_;
    int view_help_;

    QString link_list_;

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
