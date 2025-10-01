#ifndef SIGNVERIFYTHREAD_H
#define SIGNVERIFYTHREAD_H

#include <QThread>


class SignVerifyThread : public QThread
{
    Q_OBJECT
public:
    SignVerifyThread();
    ~SignVerifyThread();

    void setSignCTX( void *pCTX );
    void setVeify( bool bVerify );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( qint64 nUpdate );

protected:
    void run() override;

private:
    void *sctx_;
    bool is_verify_;

    QString src_file_;
};

#endif // SIGNVERIFYTHREAD_H
