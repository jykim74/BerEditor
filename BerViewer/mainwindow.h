#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTextBrowser>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void loadFile( const QString &filename );

private slots:
    void newFile();

private:
    Ui::MainWindow *ui;
    void createActions();
    void createStatusBar();

    QSplitter   *splitter_;
    QTreeView   *leftTree_;
    QTextBrowser    *rightBrower_;
    QAbstractItemModel  *data_;
};

#endif // MAINWINDOW_H
