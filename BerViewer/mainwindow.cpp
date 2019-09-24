#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "ber_model.h"
#include "ber_tree_view.h"

#include "insert_data_dlg.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "data_encoder_dlg.h"
#include "gen_hash_dlg.h"
#include "gen_hmac_dlg.h"
#include "oid_info_dlg.h"
#include "enc_dec_dlg.h"
#include "sign_verify_dlg.h"
#include "rsa_enc_dec_dlg.h"
#include "gen_otp_dlg.h"
#include "about_dlg.h"

#include <QtWidgets>
#include <QFileDialog>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QProcess>
#include <QFile>
#include <QtPrintSupport/qtprintsupportglobal.h>

#if defined(QT_PRINTSUPPORT_LIB)
#include <QtPrintSupport/qtprintsupportglobal.h>
#if QT_CONFIG(printer)
#if QT_CONFIG(printdialog)
#include <QPrintDialog>
#endif
#include <QPrinter>
#if QT_CONFIG(printpreviewdialog)
#include <QPrintPreviewDialog>
#endif
#endif
#endif


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
 //   ui->setupUi(this);

    initialize();

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);

    setAcceptDrops(true);
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
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);

    leftTree_ = new BerTreeView(this);


    rightText_ = new QTextEdit();
    leftTree_->setTextEdit(rightText_);
    rightTable_ = new QTableWidget;
    leftTree_->setTable(rightTable_);


    ber_model_ = new BerModel(this);

    leftTree_->setModel(ber_model_);

    hsplitter_->addWidget(leftTree_);
    hsplitter_->addWidget(vsplitter_);

    vsplitter_->addWidget(rightTable_);
    vsplitter_->addWidget(rightText_);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList<int> sizes;

    sizes << 500 << 1200;
    hsplitter_->setSizes(sizes);

    setCentralWidget(hsplitter_);
    resize( 1024, 768 );

    createTableMenu();

}

void MainWindow::createTableMenu()
{
    QStringList labels;
    labels << tr("Address") << "0" << "1" << "2" << "3" << "4" << "5" << "6" << "7" << "8" << "9"
           << "A" << "B" << "C" << "D" << "E" << "F" << tr("Text");
    rightTable_->setColumnCount(18);

    for( int i=1; i <= 16; i++ )
        rightTable_->setColumnWidth(i, 30);

    rightTable_->setHorizontalHeaderLabels( labels );
}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
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

    const QIcon saveIcon = QIcon::fromTheme("document-save", QIcon(":/images/save.png"));
    QAction *saveAct = new QAction(saveIcon, tr("&Save"), this);
    saveAct->setShortcuts(QKeySequence::Save);
    saveAct->setStatusTip(tr("Save the document to disk"));
    connect(saveAct, &QAction::triggered, this, &MainWindow::save);
    fileMenu->addAction(saveAct);
    fileToolBar->addAction(saveAct);

    const QIcon saveAsIcon = QIcon::fromTheme("document-save-as");
    QAction *saveAsAct = fileMenu->addAction(saveAsIcon, tr("Save &As..."), this, &MainWindow::saveAs);
    saveAsAct->setShortcuts(QKeySequence::SaveAs);
    saveAsAct->setStatusTip(tr("Save the document under a new name"));

    fileMenu->addSeparator();

    const QIcon printIcon = QIcon::fromTheme("documet-print", QIcon(":/images/fileprint.png"));
    QAction *printAct = new QAction(printIcon, tr("&Print"), this);
    printAct->setShortcut(QKeySequence::Print);
    connect( printAct, &QAction::triggered, this, &MainWindow::print);
    fileMenu->addAction(printAct);
    fileToolBar->addAction(printAct);

    QAction *printPreAct = new QAction(printIcon, tr("&Print Preview"), this);
    printPreAct->setStatusTip(tr( "Print preview"));
    connect( printPreAct, &QAction::triggered, this, &MainWindow::filePrintPreview);
    fileMenu->addAction(printPreAct);


    fileMenu->addSeparator();

    QAction *quitAct = new QAction( tr("&Quit"), this );
    quitAct->setStatusTip( tr( "Quit BerViewer" ));
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction(quitAct);

    QMenu *editMenu = menuBar()->addMenu(tr("&Edit"));
    QToolBar *editToolBar = addToolBar(tr("Edit"));

    /*
    const QIcon cutIcon = QIcon::fromTheme("edit-cut", QIcon(":/images/cut.png"));
    QAction *cutAct = new QAction( cutIcon, tr("Cu&t"), this);
    cutAct->setShortcut(QKeySequence::Cut);
    cutAct->setStatusTip(tr("Cut the current selection's contents to the clipboard"));
    connect( cutAct, &QAction::triggered, rightText_, &QTextEdit::cut);
    editMenu->addAction(cutAct);
    editToolBar->addAction(cutAct);
    */

    const QIcon copyIcon = QIcon::fromTheme("edit-copy", QIcon(":/images/copy.png"));
    QAction *copyAct = new QAction(copyIcon, tr("&Copy"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the current selection's contents to the clipboard"));
//    connect(copyAct, &QAction::triggered, rightText_, &QTextEdit::copy);
    connect( copyAct, &QAction::triggered, leftTree_, &BerTreeView::copy );
    editMenu->addAction(copyAct);
    editToolBar->addAction(copyAct);

    QAction *copyAsHexAct = editMenu->addAction(tr("Copy As &Hex"), leftTree_, &BerTreeView::CopyAsHex);
    copyAsHexAct->setStatusTip(tr("Copy ber data as hex"));

    QAction *copyAsBase64Act = editMenu->addAction(tr("Copy As &Base64"), leftTree_, &BerTreeView::CopyAsBase64);
    copyAsBase64Act->setStatusTip(tr("Copy ber data as base64"));

    /*
    const QIcon pasteIcon = QIcon::fromTheme("edit-paste", QIcon(":/images/paste.png"));
    QAction *pasteAct = new QAction(pasteIcon, tr("&Paste"), this);
    pasteAct->setShortcuts(QKeySequence::Paste);
    pasteAct->setStatusTip(tr("Paste the clipboard's contents into the current "
                              "selection"));
    connect(pasteAct, &QAction::triggered, rightText_, &QTextEdit::paste);
    editMenu->addAction(pasteAct);
    editToolBar->addAction(pasteAct);
    */

    menuBar()->addSeparator();

    QMenu *cryptMenu = menuBar()->addMenu(tr("&Crypt"));
    QAction *hashAct = cryptMenu->addAction(tr("&Hash"), this, &MainWindow::hash);
    hashAct->setStatusTip(tr("Generate hash value" ));

    QAction *hmacAct = cryptMenu->addAction(tr("&Hmac"), this, &MainWindow::hmac);
    hmacAct->setStatusTip(tr("Generate hmac value"));

    QAction *encDecAct = cryptMenu->addAction(tr("&Encrypt/Decrypt"), this, &MainWindow::encDec);
    encDecAct->setStatusTip(tr("Data encrypt decrypt"));

    QAction *signVerifyAct = cryptMenu->addAction(tr("&Sign/Verify"), this, &MainWindow::signVerify);
    signVerifyAct->setStatusTip(tr("Data signature and verify"));

    QAction *rsaEncDecAct = cryptMenu->addAction(tr("&RSA Encrypt/Decrypt"), this, &MainWindow::rsaEncDec);
    rsaEncDecAct->setStatusTip(tr("Data rsa encrypt decrypt"));

    QAction *genOTPAct = cryptMenu->addAction(tr("&OTP generate"), this, &MainWindow::genOTP);
    genOTPAct->setStatusTip(tr("Generate OTP value"));

    QMenu *toolMenu = menuBar()->addMenu(tr("&Tool"));

    QAction *dataEncodeAct = toolMenu->addAction(tr("Data&Encoder"), this, &MainWindow::dataEncoder);
    dataEncodeAct->setStatusTip(tr("This is tool for encoding data" ));

    QAction *oidAct = toolMenu->addAction(tr("O&ID Information"), this, &MainWindow::oidInfo);
    oidAct->setStatusTip(tr("Show OID information" ));

    QAction *insertDataAct = toolMenu->addAction(tr("&Insert data"), this, &MainWindow::insertData);
    insertDataAct->setStatusTip(tr("Insert ber data"));


    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));

    QAction *settingAct = helpMenu->addAction(tr("&Settings"), this, &MainWindow::setting);
    settingAct->setStatusTip(tr("Set the variable"));

    QAction *aboutAct = helpMenu->addAction(tr("&About BerViewer"), this, &MainWindow::about);
    aboutAct->setStatusTip(tr("Show the BerViewer"));

//    QAction *testAct = helpMenu->addAction(tr("&Test"), this, &MainWindow::test);
//    testAct->setStatusTip(tr("This is test menu"));

    menuBar()->show();
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::newFile()
{
    QString cmd = berApplet->cmd();
    QProcess *process = new QProcess();
    process->setProgram( berApplet->cmd() );
    process->start();
}

void MainWindow::insertData()
{
    int ret = -1;
    BIN binData = {0,0};

    InsertDataDlg insData(this);


    ret = insData.exec();

    if( ret == QDialog::Accepted )
    {
        QString strInput = insData.getTextData();
        strInput.remove(QRegExp("[\t\r\n\\s]"));


        if( insData.GetType() == 0 )
            JS_BIN_decodeHex( strInput.toStdString().c_str(), &binData );
        else if( insData.GetType() == 1 )
            JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binData );

        ber_model_->setBer(&binData);
        JS_BIN_reset(&binData);

        ber_model_->parseTree();

        leftTree_->viewRoot();
    }

}

void MainWindow::open()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "/home",
                                                    QDir::currentPath(),
                                                    "All files (*.*) ;; BER files (*.ber *.der);; PEM files (*.crt *.pem)" );

    if( !fileName.isEmpty() )
    {
        berFileOpen(fileName);
        file_path_ = fileName;
    }
}

void MainWindow::berFileOpen(const QString berPath)
{
    BIN binRead = {0,0};

    int ret = JS_BIN_fileRead( berPath.toLocal8Bit().toStdString().c_str(), &binRead );

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

        leftTree_->viewRoot();
        QModelIndex ri = ber_model_->index(0,0);
        leftTree_->expand(ri);
    }
}

void MainWindow::showTextMsg(const QString &msg)
{
    rightText_->setText( msg );
}


void MainWindow::about()
{
    /*
    QMessageBox::about(this, tr("About BerViewer"),
                       tr("The <b>BerViewer</b> is ASN.1 and BER viewer(Version:%1)").arg(STRINGIZE(BER_VIEWER_VERSION)));
                       */

    berApplet->aboutDlg()->show();
    berApplet->aboutDlg()->raise();
    berApplet->aboutDlg()->activateWindow();
}


void MainWindow::setting()
{
    berApplet->settingsDlg()->show();
    berApplet->settingsDlg()->raise();
    berApplet->settingsDlg()->activateWindow();
}

void MainWindow::test()
{
    berApplet->settingsDlg()->show();
    berApplet->settingsDlg()->raise();
    berApplet->settingsDlg()->activateWindow();
}

void MainWindow::dataEncoder()
{
    berApplet->dataEncoderDlg()->show();
    berApplet->dataEncoderDlg()->raise();
    berApplet->dataEncoderDlg()->activateWindow();
}

void MainWindow::hash()
{
    berApplet->genHashDlg()->show();
    berApplet->genHashDlg()->raise();
    berApplet->genHashDlg()->activateWindow();
}

void MainWindow::hmac()
{
    berApplet->genHmacDlg()->show();
    berApplet->genHmacDlg()->raise();
    berApplet->genHmacDlg()->activateWindow();
}

void MainWindow::oidInfo()
{
    berApplet->oidInfoDlg()->show();
    berApplet->oidInfoDlg()->raise();
    berApplet->oidInfoDlg()->activateWindow();
}

void MainWindow::encDec()
{
    berApplet->encDecDlg()->show();
    berApplet->encDecDlg()->raise();
    berApplet->encDecDlg()->activateWindow();
}

void MainWindow::signVerify()
{
    berApplet->signVerifyDlg()->show();
    berApplet->signVerifyDlg()->raise();
    berApplet->signVerifyDlg()->activateWindow();
}

void MainWindow::rsaEncDec()
{
    berApplet->rsaEncDecDlg()->show();
    berApplet->rsaEncDecDlg()->raise();
    berApplet->rsaEncDecDlg()->activateWindow();
}

void MainWindow::genOTP()
{
    berApplet->genOTPDlg()->show();
    berApplet->genOTPDlg()->raise();
    berApplet->genOTPDlg()->activateWindow();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    foreach (const QUrl &url, event->mimeData()->urls()) {
        QString fileName = url.toLocalFile();
        qDebug() << "Dropped file:" << fileName;
        berFileOpen(fileName);
        file_path_ = fileName;
        return;
    }
}

void MainWindow::save()
{
    if( file_path_.isEmpty() )
        saveAs();
    else {
        BIN& binBer = ber_model_->getBer();
        JS_BIN_fileWrite( &binBer, file_path_.toStdString().c_str() );
    }
}

void MainWindow::saveAs()
{
    QFileDialog fileDlg(this, tr("Save as..."));
    fileDlg.setAcceptMode(QFileDialog::AcceptSave);
    fileDlg.setDefaultSuffix("ber");

    if( fileDlg.exec() != QDialog::Accepted )
        return;

    file_path_ = fileDlg.selectedFiles().first();
    BIN& binBer = ber_model_->getBer();
    JS_BIN_fileWrite( &binBer, file_path_.toStdString().c_str());
}

void MainWindow::print()
{
#if QT_CONFIG(printdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog *dlg = new QPrintDialog(&printer, this);
    if (rightText_->textCursor().hasSelection())
        dlg->addEnabledOption(QAbstractPrintDialog::PrintSelection);
    dlg->setWindowTitle(tr("Print Document"));
    if (dlg->exec() == QDialog::Accepted)
    {
        QTextEdit txtEdit;
        QString strText = leftTree_->GetTextView();
        txtEdit.setText(strText);
        txtEdit.print(&printer);
//        rightText_->print(&printer);
    }
    delete dlg;
#endif
}


void MainWindow::filePrintPreview()
{
#if QT_CONFIG(printpreviewdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintPreviewDialog preview(&printer, this);
    connect(&preview, &QPrintPreviewDialog::paintRequested, this, &MainWindow::printPreview);
    preview.exec();
#endif
}

void MainWindow::printPreview(QPrinter *printer)
{
#ifdef QT_NO_PRINTER
    Q_UNUSED(printer);
#else
    QTextEdit txtEdit;
    QString strText = leftTree_->GetTextView();
    txtEdit.setText(strText);
    txtEdit.print(printer);
//    rightText_->print(printer);
#endif
}

void MainWindow::quit()
{
    exit(0);
}
