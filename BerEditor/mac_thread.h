#ifndef MACTHREAD_H
#define MACTHREAD_H

#include <QThread>

class MacThread : public QThread
{
    Q_OBJECT
public:
    MacThread();
    ~MacThread();

    void setCTX( bool bHSM, void *pCTX );
    void setSrcFile( const QString strSrcFile );
    int setType( int nType );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;

private:
    void *hctx_;
    int type_;
    QString src_file_;
    bool is_hsm_;
};

#endif // MACTHREAD_H
