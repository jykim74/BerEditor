#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextBrowser>

#include "ber_model.h"
#include "ber_tree_view.h"
#include "js_bin.h"

class QPrinter;

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

    void showWindow();

private slots:
    void newFile();
    void open();
    void about();
    void setting();
    void test();
    void dataEncoder();
    void hash();
    void hmac();
    void oidInfo();
    void encDec();
    void signVerify();
    void rsaEncDec();
    void genOTP();
    void insertData();
    void save();
    void saveAs();


    void print();
    void printPreview(QPrinter *printer);
    void filePrintPreview();
    void quit();

    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event );

private:
    Ui::MainWindow *ui;
    void createActions();
    void createStatusBar();

    void createTableMenu();
    void berFileOpen( const QString berPath );

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;
    BerTreeView     *leftTree_;
    QTextEdit       *rightText_;
    BerModel        *ber_model_;
    QTableWidget    *rightTable_;
    QString          file_path_;
};

#endif // MAINWINDOW_H
