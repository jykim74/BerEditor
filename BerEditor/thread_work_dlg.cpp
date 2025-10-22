#include <QThread>
#include <QTimer>
#include <QPainter>
#include <QMovie>

#include "common.h"
#include "thread_work_dlg.h"

Worker::Worker()
{

}

Worker::~Worker()
{

}

void Worker::setLenP( int nLen, int nG )
{
    len_ = nLen;
    g_ = nG;
}

void Worker::run()
{
#if 0
    // 예: 5초 동안 계산
    for (int i = 0; i < 5; ++i) {
        QThread::sleep(1);
        emit progress(i + 1);
    }
#else
    int ret = 0;
    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};



    ret = JS_PKI_genDHParam( len_, g_, &binP, &binG, &binQ );
    if( ret == 0 )
    {

    }

    emit finished( getHexString( &binP ) );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binQ );

#endif


}

ThreadWorkDlg::ThreadWorkDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    // 스크롤할 이미지 로드

    QMovie *loadGif = new QMovie( ":/images/loading.gif" );
    mLoadLabel->setMovie( loadGif );
    loadGif->start();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ThreadWorkDlg::~ThreadWorkDlg()
{
    worker->quit();
    worker->wait();

    qDebug("destory..");
}

void ThreadWorkDlg::runWork( int nLen, int nG )
{
    // 백그라운드 작업 시작
    worker = new Worker();
    worker->setLenP( nLen, nG );

    connect(worker, &Worker::progress, this, &ThreadWorkDlg::onProgress);
    connect(worker, &Worker::finished, this, &ThreadWorkDlg::onFinished);
    worker->start();
}

void ThreadWorkDlg::onProgress(int step) {
    qDebug("Background progress: %d", step);
}

void ThreadWorkDlg::onFinished( const QString strP ) {
    qDebug("Background work finished!");
    str_p_ = strP;
    close();
}

