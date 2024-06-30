#ifndef HASHTHREADRUN_H
#define HASHTHREADRUN_H

#include <QThread>

class HashThreadRun : public QThread
{
    Q_OBJECT

public:
    HashThreadRun();
    ~HashThreadRun();

    void setCTX( void *pCTX );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;

private:
    void *pctx_;
    QString src_file_;
};

#endif // HASHTHREADRUN_H
