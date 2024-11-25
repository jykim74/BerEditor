#ifndef SIGNVERIFYTHREAD_H
#define SIGNVERIFYTHREAD_H

#include <QThread>


class SignVerifyThread : public QThread
{
    Q_OBJECT
public:
    SignVerifyThread();
    ~SignVerifyThread();

    void setSignCTX( bool bHSM, void *pCTX );
    void setVerify( bool bVerify );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;

private:
    void *sctx_;
    bool is_verify_;
    bool is_hsm_;
    QString src_file_;
};

#endif // SIGNVERIFYTHREAD_H
