#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "ber_model.h"
#include "ber_tree_view.h"

#include "insert_data_dlg.h"

#include <QtWidgets>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
 //   ui->setupUi(this);

    initialize();

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);
}

MainWindow::~MainWindow()
{
//    delete ui;
    delete  ber_model_;
    delete  leftTree_;
    delete  rightText_;
}

void MainWindow::initialize()
{
    splitter_ = new QSplitter();
    leftTree_ = new BerTreeView(this);
    rightText_ = new QTextEdit();
    leftTree_->setTextEdit(rightText_);


    ber_model_ = new BerModel(this);

    leftTree_->setModel(ber_model_);

    splitter_->addWidget(leftTree_);
    splitter_->addWidget(rightText_);

    QList<int> sizes;

    sizes << 500 << 1200;
    splitter_->setSizes(sizes);

    setCentralWidget(splitter_);
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

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    QAction *openAct = new QAction( openIcon, tr("&Open..."), this );
    openAct->setShortcut(QKeySequence::Open);
    openAct->setStatusTip(tr("Open an existing file"));
    connect( openAct, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(openAct);
    fileToolBar->addAction(openAct);

    fileMenu->addSeparator();
    menuBar()->show();
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::newFile()
{
    int ret = -1;
    BIN binData = {0,0};

    InsertDataDlg insData(this);


    ret = insData.exec();

    if( ret == QDialog::Accepted )
    {
        if( insData.GetType() == 0 )
            JS_BIN_decodeHex( insData.getTextData().toStdString().c_str(), &binData );
        else if( insData.GetType() == 1 )
            JS_BIN_decodeBase64( insData.getTextData().toStdString().c_str(), &binData );

        ber_model_->setBer(&binData);
        JS_BIN_reset(&binData);

        ber_model_->parseTree();
    }

}

void MainWindow::open()
{
    QString fileName = QFileDialog::getOpenFileName(this);

    if( !fileName.isEmpty() )
    {
        BIN binRead = {0,0};

        int ret = JS_BIN_fileRead( fileName.toStdString().c_str(), &binRead );

        if( ret == 0 )
        {
            if( strstr((const char *)binRead.pVal, "-----BEGIN ") != NULL )
            {
                int type = 0;
                BIN binData = {0,0};
                char *pPEM = NULL;
                pPEM = (char *)JS_calloc( 1, binRead.nLen + 1 );
                memcpy( pPEM, binRead.pVal, binRead.nLen );
                JS_BIN_decodePEM( pPEM, &type, &binData );

                ber_model_->setBer( &binData );
                JS_BIN_reset(&binRead);
                JS_BIN_reset(&binData);
                ber_model_->parseTree();
            }
            else {
                ber_model_->setBer( &binRead );
                JS_BIN_reset(&binRead);
                ber_model_->parseTree();
            }
        }
    }
}

void MainWindow::showTextMsg(const QString &msg)
{
    rightText_->setText( msg );
}

