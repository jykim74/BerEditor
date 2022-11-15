#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextBrowser>
#include <QList>

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
    QTextEdit* logText() { return log_text_; };
    QTextEdit* infoText() { return info_text_; };
    QTableWidget* rightTable() { return right_table_; };
    void showTextMsg( const QString& msg );

    void showWindow();
    void openBer( const BIN *pBer );
    bool isChanged();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );

    QString getLog();

private slots:
    void newFile();
    void open();
    void openRecent();
    void about();
    void setting();
    void test();
    void dataEncoder();
    void keyManage();
    void hash();
    void mac();
    void keyAgree();
    void oidInfo();
    void encDec();
    void signVerify();
    void pubEncDec();
    void cms();
    void sss();
    void CAVP();
    void genOTP();
    void insertBER();
    void insertData();
    void numTrans();
    void getLdap();
    void save();
    void saveAs();
    void clearLog();


    void print();
    void printPreview(QPrinter *printer);
    void filePrintPreview();
    void quit();

    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event );
    void closeEvent(QCloseEvent *event);

private:
    Ui::MainWindow *ui;
    void createActions();
    void createStatusBar();

    void createTableMenu();
    void berFileOpen( const QString berPath );
    void setTitle( const QString strName );

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();


    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;
    BerTreeView     *left_tree_;
    QTextEdit       *log_text_;
    QTextEdit       *info_text_;
    BerModel        *ber_model_;
    QTableWidget    *right_table_;
    QString          file_path_;
};

#endif // MAINWINDOW_H
