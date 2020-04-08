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
    QTextEdit* rightText() { return right_text_; };
    QTableWidget* rightTable() { return right_table_; };
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
    void getLdap();
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
    void setTitle( const QString strName );

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;
    BerTreeView     *left_tree_;
    QTextEdit       *right_text_;
    BerModel        *ber_model_;
    QTableWidget    *right_table_;
    QString          file_path_;
};

#endif // MAINWINDOW_H
