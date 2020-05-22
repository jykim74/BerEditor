#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "ber_model.h"
#include "ber_tree_view.h"

#include "insert_data_dlg.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "data_encoder_dlg.h"
#include "gen_hash_dlg.h"
#include "gen_hmac_dlg.h"
#include "oid_info_dlg.h"
#include "enc_dec_dlg.h"
#include "sign_verify_dlg.h"
#include "rsa_enc_dec_dlg.h"
#include "gen_otp_dlg.h"
#include "get_ldap_dlg.h"
#include "key_agree_dlg.h"
#include "key_derive_dlg.h"
#include "num_trans_dlg.h"
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
    delete  left_tree_;
    delete  right_text_;
}

void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);

    left_tree_ = new BerTreeView(this);


    right_text_ = new QTextEdit();
    right_table_ = new QTableWidget;


    ber_model_ = new BerModel(this);

    left_tree_->setModel(ber_model_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget(vsplitter_);

    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget(right_text_);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList<int> sizes;

//#ifdef Q_OS_WIN32
//    sizes << 400 << 1600;
//    resize( 1940, 1024 );
//    resize( 1024, 768 );
// #else
    sizes << 400 << 1200;
    resize( 1024, 768 );
// #endif

    hsplitter_->setSizes(sizes);

    setCentralWidget(hsplitter_);


    createTableMenu();

}

void MainWindow::createTableMenu()
{    
    QStringList     labels = { tr("Field"), "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                               "A", "B", "C", "D", "E", "F", tr("Text") };

    right_table_->horizontalHeader()->setStretchLastSection(true);
    right_table_->setColumnCount(18);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

    right_table_->horizontalHeader()->setStyleSheet( style );
    right_table_->setColumnWidth(0, 100);


    for( int i=1; i <= 16; i++ )
        right_table_->setColumnWidth(i, 30);

    right_table_->setHorizontalHeaderLabels( labels );
    right_table_->verticalHeader()->setVisible(false);
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


    const QIcon copyIcon = QIcon::fromTheme("edit-copy", QIcon(":/images/copy.png"));
    QAction *copyAct = new QAction(copyIcon, tr("&Copy"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the current selection's contents to the clipboard"));
    connect( copyAct, &QAction::triggered, left_tree_, &BerTreeView::copy );
    editMenu->addAction(copyAct);
    editToolBar->addAction(copyAct);

    QAction *copyAsHexAct = editMenu->addAction(tr("Copy As &Hex"), left_tree_, &BerTreeView::CopyAsHex);
    copyAsHexAct->setStatusTip(tr("Copy ber data as hex"));

    QAction *copyAsBase64Act = editMenu->addAction(tr("Copy As &Base64"), left_tree_, &BerTreeView::CopyAsBase64);
    copyAsBase64Act->setStatusTip(tr("Copy ber data as base64"));

    const QIcon expandAllIcon = QIcon::fromTheme("expand-all", QIcon(":/images/expand_all.png"));
    QAction *expandAllAct = new QAction(expandAllIcon, tr("&Expand All"), this );
    expandAllAct->setShortcut( QKeySequence(Qt::Key_F5) );
    expandAllAct->setStatusTip(tr("Show all nodes"));
    connect( expandAllAct, &QAction::triggered, left_tree_, &BerTreeView::treeExpandAll );
    editMenu->addAction(expandAllAct);
    editToolBar->addAction(expandAllAct);

    const QIcon expandNodeIcon = QIcon::fromTheme("expand-node", QIcon(":/images/expand_node.png"));
    QAction *expandNodeAct = new QAction(expandNodeIcon, tr("&Expand Node"), this );
    expandNodeAct->setStatusTip(tr("Show node"));
    expandNodeAct->setShortcut( QKeySequence(Qt::Key_F6));
    connect( expandNodeAct, &QAction::triggered, left_tree_, &BerTreeView::treeExpandNode );
    editMenu->addAction(expandNodeAct);
    editToolBar->addAction(expandNodeAct);

    const QIcon collapseAllIcon = QIcon::fromTheme("collapse-all", QIcon(":/images/collapse_all.png"));
    QAction *collapseAllAct = new QAction(collapseAllIcon, tr("&Collapse All"), this );
    collapseAllAct->setStatusTip(tr("Collapse all nodes"));
    collapseAllAct->setShortcut( QKeySequence(Qt::Key_F7));
    connect( collapseAllAct, &QAction::triggered, left_tree_, &BerTreeView::treeCollapseAll );
    editMenu->addAction(collapseAllAct);
    editToolBar->addAction(collapseAllAct);

    const QIcon collapseNodeIcon = QIcon::fromTheme("collapse-node", QIcon(":/images/collapse_node.png"));
    QAction *collapseNodeAct = new QAction(collapseNodeIcon, tr("&Collapse Node"), this );
    collapseNodeAct->setStatusTip(tr("Show node"));
    collapseNodeAct->setShortcut( QKeySequence(Qt::Key_F8));
    connect( collapseNodeAct, &QAction::triggered, left_tree_, &BerTreeView::treeCollapseNode );
    editMenu->addAction(collapseNodeAct);
    editToolBar->addAction(collapseNodeAct);

    menuBar()->addSeparator();

    QMenu *cryptMenu = menuBar()->addMenu(tr("&Crypt"));

    QAction *keyDeriveAct = cryptMenu->addAction(tr("&KeyDerive"), this, &MainWindow::keyDerive);
    keyDeriveAct->setStatusTip(tr("Key Derive function" ));

    QAction *hashAct = cryptMenu->addAction(tr("&Hash"), this, &MainWindow::hash);
    hashAct->setStatusTip(tr("Generate hash value" ));

    QAction *hmacAct = cryptMenu->addAction(tr("H&mac"), this, &MainWindow::hmac);
    hmacAct->setStatusTip(tr("Generate hmac value"));

    QAction *encDecAct = cryptMenu->addAction(tr("&Encrypt/Decrypt"), this, &MainWindow::encDec);
    encDecAct->setStatusTip(tr("Data encrypt decrypt"));

    QAction *signVerifyAct = cryptMenu->addAction(tr("&Sign/Verify"), this, &MainWindow::signVerify);
    signVerifyAct->setStatusTip(tr("Data signature and verify"));

    QAction *rsaEncDecAct = cryptMenu->addAction(tr("&RSA Encrypt/Decrypt"), this, &MainWindow::rsaEncDec);
    rsaEncDecAct->setStatusTip(tr("Data rsa encrypt decrypt"));

    QAction *keyAgreeAct = cryptMenu->addAction(tr("&Key Agreement"), this, &MainWindow::keyAgree);
    keyAgreeAct->setStatusTip(tr("Key Agreement"));

    QAction *genOTPAct = cryptMenu->addAction(tr("&OTP generate"), this, &MainWindow::genOTP);
    genOTPAct->setStatusTip(tr("Generate OTP value"));

    QMenu *toolMenu = menuBar()->addMenu(tr("&Tool"));
    QToolBar *toolToolBar = addToolBar(tr("Tool"));

    const QIcon dataTransIcon = QIcon::fromTheme("data-trans", QIcon(":/images/data_trans.png"));
    QAction *dataEncodeAct = new QAction( dataTransIcon, tr("Data&Encoder"), this );
    connect( dataEncodeAct, &QAction::triggered, this, &MainWindow::dataEncoder );
    dataEncodeAct->setStatusTip(tr("This is tool for encoding data" ));
    toolMenu->addAction( dataEncodeAct );
    toolToolBar->addAction( dataEncodeAct );

    const QIcon numTransIcon = QIcon::fromTheme("number-trans", QIcon(":/images/number.jpg"));
    QAction *numTransAct = new QAction( numTransIcon, tr("&NumTrans"), this);
    connect( numTransAct, &QAction::triggered, this, &MainWindow::numTrans );
    numTransAct->setStatusTip(tr("Number transmission" ));
    toolMenu->addAction( numTransAct );
    toolToolBar->addAction( numTransAct );

    QAction *oidAct = toolMenu->addAction(tr("O&ID Information"), this, &MainWindow::oidInfo);
    oidAct->setStatusTip(tr("Show OID information" ));

    const QIcon insertIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/insert.png"));
    QAction *insertDataAct = new QAction(insertIcon, tr("&Insert data"), this);
    connect( insertDataAct, &QAction::triggered, this, &MainWindow::insertData );
    insertDataAct->setStatusTip(tr("Insert ber data"));
    toolMenu->addAction( insertDataAct );
    toolToolBar->addAction( insertDataAct );

    QAction *getLdapAct = toolMenu->addAction(tr("&Get LDAP data"), this, &MainWindow::getLdap);
    getLdapAct->setStatusTip(tr("Get Ber data from LDAP server"));


    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));

    QAction *settingAct = helpMenu->addAction(tr("&Settings"), this, &MainWindow::setting);
    settingAct->setStatusTip(tr("Set the variable"));

    QAction *aboutAct = helpMenu->addAction(tr("&About BerViewer"), this, &MainWindow::about);
    aboutAct->setStatusTip(tr("Show the BerViewer"));

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

        left_tree_->header()->setVisible(false);
        left_tree_->viewRoot();

        setTitle( QString("Unknown" ));
    }

}

void MainWindow::numTrans()
{
    NumTransDlg numTransDlg;
    numTransDlg.exec();
}

void MainWindow::open()
{
    bool bSavePath = berApplet->settingsMgr()->isSaveOpenFolder();
    QString strPath = QDir::currentPath();

    if( bSavePath )
    {
        QSettings settings;
        settings.beginGroup( "berviewer" );
        strPath = settings.value( "openPath", "" ).toString();
        settings.endGroup();
    }

    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "BerViewer file open",
                                                    strPath,
                                                    "All files (*.*) ;; BER files (*.ber *.der);; PEM files (*.crt *.pem)" );

    if( !fileName.isEmpty() )
    {
        berFileOpen(fileName);
        file_path_ = fileName;
        setTitle( fileName );

        if( bSavePath )
        {
            QFileInfo fileInfo(fileName);
            QString strDir = fileInfo.dir().path();

            QSettings settings;
            settings.beginGroup("berviewer");
            settings.setValue( "openPath", strDir );
            settings.endGroup();
        }
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

        left_tree_->header()->setVisible(false);
        left_tree_->viewRoot();
        QModelIndex ri = ber_model_->index(0,0);
        left_tree_->expand(ri);
    }
}

void MainWindow::setTitle( const QString strName )
{
   QString strWinTitle = QString( "%1 - %2" ).arg( berApplet->getBrand() ).arg( strName );

   setWindowTitle( strWinTitle );
}

void MainWindow::showTextMsg(const QString &msg)
{
    right_text_->setText( msg );
}


void MainWindow::about()
{
    /*
    QMessageBox::about(this, tr("About BerViewer"),
                       tr("The <b>BerViewer</b> is ASN.1 and BER viewer(Version:%1)").arg(STRINGIZE(BER_VIEWER_VERSION)));
                       */

    AboutDlg aboutDlg;
    aboutDlg.exec();
}


void MainWindow::setting()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::test()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::dataEncoder()
{
    DataEncoderDlg dataEncoderDlg;
    dataEncoderDlg.exec();
}

void MainWindow::keyDerive()
{
    KeyDeriveDlg keyDeriveDlg;
    keyDeriveDlg.exec();
}

void MainWindow::hash()
{
    GenHashDlg genHashDlg;
    genHashDlg.exec();
}

void MainWindow::hmac()
{
    GenHmacDlg genHmacDlg;
    genHmacDlg.exec();
}

void MainWindow::keyAgree()
{
    KeyAgreeDlg keyAgreeDlg;
    keyAgreeDlg.exec();
}

void MainWindow::oidInfo()
{
    OIDInfoDlg oidInfoDlg;
    oidInfoDlg.exec();
}

void MainWindow::encDec()
{
    EncDecDlg encDecDlg;
    encDecDlg.exec();
}

void MainWindow::signVerify()
{
    SignVerifyDlg signVerifyDlg;
    signVerifyDlg.exec();
}

void MainWindow::rsaEncDec()
{
    RSAEncDecDlg rsaEncDecDlg;
    rsaEncDecDlg.exec();
}

void MainWindow::genOTP()
{
    GenOTPDlg genOTPDlg;
    genOTPDlg.exec();
}

void MainWindow::getLdap()
{
    int ret = -1;
    GetLdapDlg getLdapDlg;
    ret = getLdapDlg.exec();

    if( ret == QDialog::Accepted )
    {
        ber_model_->setBer(&getLdapDlg.getData());

        ber_model_->parseTree();

        left_tree_->header()->setVisible(false);
        left_tree_->viewRoot();

        setTitle( QString("Unknown" ));
    }
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

        setTitle( fileName );
        return;
    }
}

void MainWindow::save()
{
    if( file_path_.isEmpty() )
        saveAs();
    else {
        if( berApplet->yesOrNoBox( tr("Do you want to overwrite %1 as BER file?").arg(file_path_), this ) == 0)
        {
            return;
        }

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
    if (right_text_->textCursor().hasSelection())
        dlg->addEnabledOption(QAbstractPrintDialog::PrintSelection);
    dlg->setWindowTitle(tr("Print Document"));
    if (dlg->exec() == QDialog::Accepted)
    {
        QTextEdit txtEdit;
        QString strText = left_tree_->GetTextView();
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
    QString strText = left_tree_->GetTextView();
    txtEdit.setText(strText);
    txtEdit.print(printer);
//    rightText_->print(printer);
#endif
}

void MainWindow::quit()
{
    exit(0);
}
