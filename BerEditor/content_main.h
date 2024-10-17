#ifndef CONTENT_MAIN_H
#define CONTENT_MAIN_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QMenu>
#include <QtHelp/QHelpEngine>
#include <QPrinter>
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
    void clickOpenURI();

    void actSave();
    void actPrint();
    void actPrintPreview();
    void actExpandAll();
    void actExpandNode();
    void actCollapseAll();
    void actCollapseNode();
    void actShowMenu();
    void actHideMenu();
    void actQuit();

    void printPreview(QPrinter *printer);

private:
    void createActions();
    void createStatusBar();
    void createDockWindows();

    void makeASNMenu( QTreeWidgetItem* parent );
    void makeRFCMenu( QTreeWidgetItem* parent );
    void makePKIXMenu( QTreeWidgetItem* parent );

    void initialize();


    QHelpEngine* help_;
};

#endif // CONTENT_MAIN_H
