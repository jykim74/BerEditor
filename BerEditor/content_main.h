#ifndef CONTENT_MAIN_H
#define CONTENT_MAIN_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QMenu>
#include <QtHelp/QHelpEngine>
#include "ui_content_main.h"

namespace Ui {
class ContentMain;
}

class ContentMain : public QMainWindow, public Ui::ContentMain
{
    Q_OBJECT

public:
    explicit ContentMain(QWidget *parent = nullptr);
    ~ContentMain();

private slots:
    void clickMenu();

private:
    void createActions();
    void createStatusBar();
    void createDockWindows();

    void initialize();
    QHelpEngine* help_;
};

#endif // CONTENT_MAIN_H
