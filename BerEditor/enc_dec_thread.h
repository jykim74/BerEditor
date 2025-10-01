#ifndef ENCDECTHREAD_H
#define ENCDECTHREAD_H

#include <QThread>

class EncDecThread : public QThread
{
    Q_OBJECT

public:
    EncDecThread();
    ~EncDecThread();

    void setCTX( void *pCTX );
    void setAE( bool bAE );
    void setMethod( bool bDec );
    void setMode( const QString strMode );
    void setSrcFile( const QString strSrcFile );
    void setDstFile( const QString strDstFile );

signals:
    void taskFinished();
    void taskUpdate( qint64 nUpdate );

protected:
    void run() override;

private:
    void *ctx_;
    bool is_dec_;
    bool is_ae_;

    QString mode_;
    QString src_file_;
    QString dst_file_;
};

#endif // ENCDECTHREAD_H
