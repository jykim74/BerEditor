#include <QThread>
#include <QTimer>
#include <QPainter>
#include "thread_work_dlg.h"



ThreadWorkDlg::ThreadWorkDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    // 스크롤할 이미지 로드
    pixmap = QPixmap(":/images/sample.jpg");
    if (pixmap.isNull()) {
        pixmap = QPixmap(600, 200);
        pixmap.fill(Qt::darkGray);
    }

    // 타이머로 스크롤 애니메이션
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &ThreadWorkDlg::scrollImage );
    timer->start(30); // 30ms마다 스크롤 (약 33fps)

    // 백그라운드 작업 시작
    worker = new Worker();
    connect(worker, &Worker::progress, this, &ThreadWorkDlg::onProgress);
    connect(worker, &Worker::finished, this, &ThreadWorkDlg::onFinished);
    worker->start();
}

ThreadWorkDlg::~ThreadWorkDlg()
{
    worker->quit();
    worker->wait();
}

void ThreadWorkDlg::paintEvent(QPaintEvent *) {
    QPainter p(this);
    int w = pixmap.width();
    int x = -offset % w;
    p.drawPixmap(x, 0, pixmap);
    p.drawPixmap(x + w, 0, pixmap);
}

void ThreadWorkDlg::scrollImage() {
    offset += 2; // 스크롤 속도
    if (offset > pixmap.width())
        offset = 0;
    update();
}

void ThreadWorkDlg::onProgress(int step) {
    qDebug("Background progress: %d", step);
}

void ThreadWorkDlg::onFinished() {
    qDebug("Background work finished!");
    timer->stop();
}
