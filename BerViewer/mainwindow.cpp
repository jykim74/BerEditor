#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
 //   ui->setupUi(this);

    splitter_ = new QSplitter();
    leftTree_ = new QTreeView();
    rightBrower_ = new QTextBrowser();




    splitter_->addWidget(leftTree_);
    splitter_->addWidget(rightBrower_);

    QList<int> sizes;

    sizes << 300 << 800;
    splitter_->setSizes(sizes);

    setCentralWidget(splitter_);

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);
}

MainWindow::~MainWindow()
{
//    delete ui;
}


void MainWindow::loadFile(const QString &filename)
{

}

void MainWindow::createActions()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    QAction *newAct = new QAction( newIcon, tr("&New"), this );
    newAct->setShortcut(QKeySequence::New);
    newAct->setStatusTip(tr("Create a new file"));
    connect( newAct, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction(newAct);
    fileToolBar->addAction(newAct);

    fileMenu->addSeparator();
    menuBar()->show();
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::newFile()
{

}
