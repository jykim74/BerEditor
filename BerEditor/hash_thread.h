#ifndef HASHTHREAD_H
#define HASHTHREAD_H

#include <QThread>

class HashThread : public QThread
{
    Q_OBJECT

public:
    HashThread();
    ~HashThread();

    void setCTX( void *pCTX );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( qint64 nUpdate );

protected:
    void run() override;

private:
    void *pctx_;
    QString src_file_;
};

#endif // HASHTHREADRUN_H
