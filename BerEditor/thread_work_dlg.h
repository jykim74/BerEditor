#ifndef THREAD_WORK_DLG_H
#define THREAD_WORK_DLG_H

#include <QDialog>
#include <QThread>
#include "ui_thread_work_dlg.h"
#include "js_pki.h"

namespace Ui {
class ThreadWorkDlg;
}

class Worker : public QThread {
    Q_OBJECT
public:
    Worker();
    ~Worker();

    void setLenP( int nLen, int nG );

    void run() override;

signals:
    void progress(int);
    void finished( const QString strP );

private :
    int len_;
    int g_;
};

class ThreadWorkDlg : public QDialog, public Ui::ThreadWorkDlg
{
    Q_OBJECT

public:
    explicit ThreadWorkDlg(QWidget *parent = nullptr);
    ~ThreadWorkDlg();

    void runWork( int nLen, int nG );
    const QString getP() { return str_p_; };

private slots:
    void onProgress(int step);
    void onFinished( const QString strP );

private:
    Worker *worker;
    QString str_p_;;
};

#endif // THREAD_WORK_DLG_H
