#ifndef LDTHASHTHREAD_H
#define LDTHASHTHREAD_H

#include <QThread>

#include "js_pki.h"
#include "js_error.h"

class LDTHashThread : public QThread
{
    Q_OBJECT
public:
    LDTHashThread();
    ~LDTHashThread();

    void setStop( bool bStop );
    void setContent( const QString strContent );
    void setHash( const QString strHash );
    void setFullLengthBits( qint64 nLengthBits );

    void makeLDT();

signals:
    void taskFinished( int ret );
    void taskUpdate( qint64 nCurLength );
    void taskLastUpdate( const QString strMD );

protected:
    void run() override;

private:
    bool is_stop_;
    QString content_;
    QString hash_;
    qint64 full_length_bits_;
};

#endif // LDTHASHTHREAD_H
