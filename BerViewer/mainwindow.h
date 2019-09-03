#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTextBrowser>

#include "ber_model.h"
#include "ber_tree_view.h"
#include "js_bin.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void initialize();
    void loadFile( const QString &filename );
    QTextEdit* getRightText() { return rightText_; };
    void showTextMsg( const QString& msg );

private slots:
    void newFile();
    void open();

private:
    Ui::MainWindow *ui;
    void createActions();
    void createStatusBar();

    QSplitter   *splitter_;
    BerTreeView   *leftTree_;
    QTextEdit       *rightText_;
    BerModel        *ber_model_;

};

#endif // MAINWINDOW_H
