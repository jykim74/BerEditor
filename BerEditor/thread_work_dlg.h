#ifndef THREAD_WORK_DLG_H
#define THREAD_WORK_DLG_H

#include <QDialog>
#include <QThread>
#include "ui_thread_work_dlg.h"

namespace Ui {
class ThreadWorkDlg;
}

class Worker : public QThread {
    Q_OBJECT
public:
    void run() override {
        // 예: 5초 동안 계산
        for (int i = 0; i < 5; ++i) {
            QThread::sleep(1);
            emit progress(i + 1);
        }
        emit finished();
    }

signals:
    void progress(int);
    void finished();
};

class ThreadWorkDlg : public QDialog, public Ui::ThreadWorkDlg
{
    Q_OBJECT

public:
    explicit ThreadWorkDlg(QWidget *parent = nullptr);
    ~ThreadWorkDlg();

private slots:
    void scrollImage();
    void onProgress(int step);
    void onFinished();

protected:
    void paintEvent(QPaintEvent *);

private:

private:
    QPixmap pixmap;
    QTimer *timer;
    Worker *worker;
    int offset;

};

#endif // THREAD_WORK_DLG_H
