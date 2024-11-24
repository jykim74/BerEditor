#ifndef HASHTHREAD_H
#define HASHTHREAD_H

#include <QThread>
#include "js_pkcs11.h"

class HashThread : public QThread
{
    Q_OBJECT

public:
    HashThread();
    ~HashThread();

    void setCTX( bool bHSM, void *pCTX );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;

private:
    void *pctx_;
    bool is_hsm_;

    QString src_file_;
};

#endif // HASHTHREADRUN_H
