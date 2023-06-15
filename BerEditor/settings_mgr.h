#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT
private:

public:
    SettingsMgr(QObject *parent = nullptr);

    void setShowPartOnly( bool val );
    bool showPartOnly();

    void setOIDConfigPath( const QString& strPath );
    QString OIDConfigPath();

    void setShowLogTab( bool bVal );
    bool showLogTab();

    void setDefaultHash( const QString& strHash );
    QString getDefaultHash();
    QString defaultHash() { return default_hash_; };

    void setFileReadSize( int size );
    int getFileReadSize();
    int fileReadSize() { return file_read_size_; };
signals:

private:
    void initialize();

private:
    QString default_hash_;
    int file_read_size_;

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
