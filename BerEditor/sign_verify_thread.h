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
    void setHashCTX( void *pCTX );
    void setEdDSA( bool bEdDSA );
    void setVeify( bool bVerify );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;

private:
    void *sctx_;
    void *hctx_;
    bool is_eddsa_;
    bool is_verify_;

    QString src_file_;
};

#endif // SIGNVERIFYTHREAD_H
