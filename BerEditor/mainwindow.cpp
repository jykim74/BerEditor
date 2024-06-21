/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
// #include "ui_mainwindow.h"

#include "ber_model.h"
#include "ber_tree_view.h"

#include "insert_data_dlg.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "data_encoder_dlg.h"
#include "gen_hash_dlg.h"
#include "gen_mac_dlg.h"
#include "oid_info_dlg.h"
#include "enc_dec_dlg.h"
#include "sign_verify_dlg.h"
#include "pub_enc_dec_dlg.h"
#include "gen_otp_dlg.h"
#include "get_uri_dlg.h"
#include "key_agree_dlg.h"
#include "key_man_dlg.h"
#include "num_trans_dlg.h"
#include "about_dlg.h"
#include "cms_dlg.h"
#include "sss_dlg.h"
#include "cavp_dlg.h"
#include "insert_ber_dlg.h"
#include "cert_pvd_dlg.h"
#include "lcn_info_dlg.h"
#include "ssl_verify_dlg.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "csr_info_dlg.h"
#include "vid_dlg.h"
#include "bn_calc_dlg.h"
#include "key_pair_man_dlg.h"
#include "ocsp_client_dlg.h"
#include "tsp_client_dlg.h"
#include "cmp_client_dlg.h"
#include "scep_client_dlg.h"
#include "cert_man_dlg.h"
#include "common.h"

#include "js_pki_tools.h"

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

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    log_halt_ = false;

    initialize();

    createCryptoDlg();
    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);

    setAcceptDrops(true);
}

MainWindow::~MainWindow()
{
    recent_file_list_.clear();

    delete ber_model_;
    delete left_tree_;
    delete log_text_;
    delete info_text_;
    delete right_table_;
    delete right_xml_;

    delete key_man_dlg_;
    delete gen_hash_dlg_;
    delete gen_mac_dlg_;
    delete enc_dec_dlg_;
    delete sign_verify_dlg_;
    delete pub_enc_dec_dlg_;
    delete key_agree_dlg_;
    delete cms_dlg_;
    delete sss_dlg_;
    delete cert_pvd_dlg_;
    delete gen_otp_dlg_;
    delete cavp_dlg_;
    delete ssl_verify_dlg_;
    delete vid_dlg_;
    delete bn_calc_dlg_;
    delete key_pair_man_dlg_;
    delete ocsp_client_dlg_;
    delete tsp_client_dlg_;
    delete cmp_client_dlg_;
    delete scep_client_dlg_;
    delete cert_man_dlg_;

    delete table_tab_;
    delete text_tab_;
    delete vsplitter_;
    delete hsplitter_;
}

void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);

    left_tree_ = new BerTreeView(this);

    log_text_ = new QTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new QTextEdit;
    info_text_->setReadOnly(true);

    right_table_ = new QTableWidget;
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
//    right_table_->setSelectionMode( QAbstractItemView::ExtendedSelection );
//    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    right_table_->setSelectionMode(QAbstractItemView::MultiSelection);

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(rightTableCustomMenu(const QPoint&)));

    ber_model_ = new BerModel(this);

    left_tree_->setModel(ber_model_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget(vsplitter_);

    table_tab_ = new QTabWidget;
    table_tab_->setTabPosition( QTabWidget::South );
    table_tab_->addTab( right_table_, tr( "Hex" ));

    right_xml_ = new QTextEdit;
    right_xml_->setReadOnly(true);
    table_tab_->addTab( right_xml_, tr( "XML" ));

    right_text_ = new QTextEdit;
    right_text_->setReadOnly(true);
    table_tab_->addTab( right_text_, tr( "Text" ));



    vsplitter_->addWidget( table_tab_ );

    text_tab_ = new QTabWidget;
    vsplitter_->addWidget( text_tab_ );
    text_tab_->setTabPosition( QTabWidget::South );
    text_tab_->addTab( info_text_, tr("information") );
    text_tab_->addTab( log_text_, tr( "Log" ));

    if( berApplet->isLicense() == false )
    {
        table_tab_->setTabEnabled( 1, false );
        table_tab_->setTabEnabled( 2, false );

        text_tab_->setTabEnabled( 1, false );
    }

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList<int> sizes;
    sizes << 400 << 1200;

#ifdef Q_OS_MAC
    resize( 960, 760 );
#else
#ifdef Q_OS_WIN
    resize( 940, 760 );
#else
    resize( 1020, 760 );
#endif
#endif

    hsplitter_->setSizes(sizes);

    setCentralWidget(hsplitter_);
    createTableMenu();
    setTitle( "" );
}

void MainWindow::createTableMenu()
{    
    QStringList     labels = { tr("Field"), "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                               "A", "B", "C", "D", "E", "F", tr("Text") };

    right_table_->horizontalHeader()->setMinimumSectionSize(10);  // 최소 column width 지정
    right_table_->horizontalHeader()->setStretchLastSection(true);
    right_table_->setColumnCount(18);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

    right_table_->horizontalHeader()->setStyleSheet( style );


#ifdef Q_OS_WIN32
    right_table_->setColumnWidth(0, 70);
#else
#ifdef Q_OS_LINUX
    right_table_->setColumnWidth(0, 90);
#else
    right_table_->setColumnWidth(0, 80);
#endif
#endif

    for( int i=1; i <= 16; i++ )
        right_table_->setColumnWidth(i, 30);

    right_table_->setColumnWidth( 17, 100 );

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
    BIN binData = {0,0};

    JS_BIN_fileReadBER( filename.toLocal8Bit().toStdString().c_str(), &binData );

    decodeData( &binData, filename );
    JS_BIN_reset( &binData );
}

void MainWindow::createActions()
{
    int nWidth = 24;
    int nHeight = 24;
    int nSpacing = 0;

    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

    fileToolBar->setIconSize( QSize(nWidth,nHeight) );
    fileToolBar->layout()->setSpacing(nSpacing);

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

    const QIcon openCertIcon = QIcon::fromTheme("document-cert", QIcon(":/images/cert.png"));
    QAction *openCertAct = new QAction( openCertIcon, tr("&Open Certificate"), this );
    openCertAct->setShortcut(QKeySequence(Qt::Key_F2));
    openCertAct->setStatusTip(tr("Open a certificate"));
    connect( openCertAct, &QAction::triggered, this, &MainWindow::openCert);
    fileMenu->addAction(openCertAct);

    const QIcon openCRLIcon = QIcon::fromTheme("document-crl", QIcon(":/images/crl.png"));
    QAction *openCRLAct = new QAction( openCRLIcon, tr("&Open CRL"), this );
    openCRLAct->setShortcut(QKeySequence(Qt::Key_F3));
    openCRLAct->setStatusTip(tr("Open a CRL"));
    connect( openCRLAct, &QAction::triggered, this, &MainWindow::openCRL);
    fileMenu->addAction(openCRLAct);

    const QIcon openCSRIcon = QIcon::fromTheme("document-csr", QIcon(":/images/csr.png"));
    QAction *openCSRAct = new QAction( openCSRIcon, tr("&Open CSR"), this );
    openCSRAct->setShortcut(QKeySequence(Qt::Key_F4));
    openCSRAct->setStatusTip(tr("Open a CSR"));
    connect( openCSRAct, &QAction::triggered, this, &MainWindow::openCSR);
    fileMenu->addAction(openCSRAct);

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

    QAction* recentFileAct = NULL;
    for( auto i = 0; i < kMaxRecentFiles; ++i )
    {
        recentFileAct = new QAction(this);
        recentFileAct->setVisible(false);

        QObject::connect( recentFileAct, &QAction::triggered, this, &MainWindow::openRecent );
        recent_file_list_.append( recentFileAct );
    }

    QMenu* recentMenu = fileMenu->addMenu( tr("Recent Files" ) );
    for( int i = 0; i < kMaxRecentFiles; i++ )
    {
        recentMenu->addAction( recent_file_list_.at(i) );
    }

    updateRecentActionList();

    fileMenu->addSeparator();

    const QIcon printIcon = QIcon::fromTheme("documet-print", QIcon(":/images/fileprint.png"));
    QAction *printAct = new QAction(printIcon, tr("&Print"), this);
    printAct->setShortcut(QKeySequence::Print);
    connect( printAct, &QAction::triggered, this, &MainWindow::print);
    fileMenu->addAction(printAct);
//    fileToolBar->addAction(printAct);

    QAction *printPreAct = new QAction(printIcon, tr("&Print Preview"), this);
    printPreAct->setStatusTip(tr( "Print preview"));
    connect( printPreAct, &QAction::triggered, this, &MainWindow::filePrintPreview);
    fileMenu->addAction(printPreAct);


    fileMenu->addSeparator();

    QAction *quitAct = new QAction( tr("&Quit"), this );
    quitAct->setStatusTip( tr( "Quit BerEditor" ));
    quitAct->setShortcut(QKeySequence::Quit);
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction(quitAct);

    QMenu *editMenu = menuBar()->addMenu(tr("&Edit"));
    QToolBar *editToolBar = addToolBar(tr("Edit"));

    editToolBar->setIconSize( QSize(nWidth,nHeight));
    editToolBar->layout()->setSpacing(nSpacing);

    const QIcon copyIcon = QIcon::fromTheme("edit-copy", QIcon(":/images/copy.png"));
    QAction *copyAct = new QAction(copyIcon, tr("&Copy Information"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the current selection's contents to the clipboard"));
    connect( copyAct, &QAction::triggered, left_tree_, &BerTreeView::copy );
    editMenu->addAction(copyAct);
//    editToolBar->addAction(copyAct);

    QAction *copyAsHexAct = new QAction(copyIcon, tr("Copy As &Hex"), this);
    copyAsHexAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_X));
    copyAsHexAct->setStatusTip(tr("Copy ber data as hex"));
    connect( copyAsHexAct, &QAction::triggered, left_tree_, &BerTreeView::CopyAsHex );
    editMenu->addAction( copyAsHexAct );

    QAction *copyAsBase64Act = new QAction(copyIcon, tr("Copy As &Base64"), this);
    copyAsBase64Act->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_B));
    copyAsBase64Act->setStatusTip(tr("Copy ber data as base64"));
    connect( copyAsBase64Act, &QAction::triggered, left_tree_, &BerTreeView::CopyAsBase64 );
    editMenu->addAction( copyAsBase64Act );

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

    QMenu *toolMenu = menuBar()->addMenu(tr("&Tool"));
    QToolBar *toolToolBar = addToolBar(tr("Tool"));


    toolToolBar->setIconSize( QSize(nWidth,nHeight));
    toolToolBar->layout()->setSpacing(nSpacing);


    const QIcon dataTransIcon = QIcon::fromTheme("data-trans", QIcon(":/images/data_trans.png"));
    QAction *dataEncodeAct = new QAction( dataTransIcon, tr("Data&Encoder"), this );
    dataEncodeAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_E));
    connect( dataEncodeAct, &QAction::triggered, this, &MainWindow::dataEncoder );
    dataEncodeAct->setStatusTip(tr("This is tool for encoding data" ));
    toolMenu->addAction( dataEncodeAct );
    toolToolBar->addAction( dataEncodeAct );

    const QIcon numTransIcon = QIcon::fromTheme("number-trans", QIcon(":/images/two.png"));
    QAction *numTransAct = new QAction( numTransIcon, tr("&NumTrans"), this);
    numTransAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T));
    connect( numTransAct, &QAction::triggered, this, &MainWindow::numTrans );
    numTransAct->setStatusTip(tr("Number transmission" ));
    toolMenu->addAction( numTransAct );
//    toolToolBar->addAction( numTransAct );

    const QIcon oidIcon = QIcon::fromTheme("tool-oid", QIcon(":/images/oid.png"));
    QAction *oidAct = new QAction(oidIcon, tr("&OID Information"), this);
    oidAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_O));
    connect( oidAct, &QAction::triggered, this, &MainWindow::oidInfo );
    oidAct->setStatusTip(tr("Show OID information"));
    toolMenu->addAction( oidAct );
    toolToolBar->addAction( oidAct );

    const QIcon berIcon = QIcon::fromTheme("ber-insert", QIcon(":/images/ber.png"));
    QAction *insertBerAct = new QAction(berIcon, tr("Insert &BER"), this);
    insertBerAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_B));
    connect( insertBerAct, &QAction::triggered, this, &MainWindow::insertBER );
    insertBerAct->setStatusTip(tr("Insert BER record"));
    toolMenu->addAction( insertBerAct );
    toolToolBar->addAction( insertBerAct );

    if( berApplet->isLicense() == false )
    {
        insertBerAct->setEnabled( false );
    }

    const QIcon insertIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/insert.png"));
    QAction *insertDataAct = new QAction(insertIcon, tr("&Insert Data"), this);
    insertDataAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_D));
    connect( insertDataAct, &QAction::triggered, this, &MainWindow::insertData );
    insertDataAct->setStatusTip(tr("Insert ber data"));
    toolMenu->addAction( insertDataAct );
    toolToolBar->addAction( insertDataAct );

    const QIcon uriIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/uri.png"));
    QAction *getURIAct = new QAction(uriIcon, tr("&Get URI data"), this);
    getURIAct->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_U));
    connect( getURIAct, &QAction::triggered, this, &MainWindow::getURI );
    getURIAct->setStatusTip(tr("Get Ber data from URI"));
    toolMenu->addAction( getURIAct );
    toolToolBar->addAction( getURIAct );

    menuBar()->addSeparator();

    QMenu *cryptMenu = menuBar()->addMenu(tr("&Cryptogram"));
    QToolBar *cryptToolBar = addToolBar( "Cryptogram" );

    cryptToolBar->setIconSize( QSize(nWidth,nHeight));
    cryptToolBar->layout()->setSpacing(nSpacing);

    const QIcon keyIcon = QIcon::fromTheme("key-man", QIcon(":/images/key.png"));
    QAction *keyManAct = new QAction( keyIcon, tr("&KeyManage"), this );
    keyManAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_K));
    connect( keyManAct, &QAction::triggered, this, &MainWindow::keyManage );
    keyManAct->setStatusTip(tr("Key Manage function" ));
    cryptMenu->addAction( keyManAct );
//    cryptToolBar->addAction( keyManAct );

    const QIcon hashIcon = QIcon::fromTheme("Hash", QIcon(":/images/hash.png"));
    QAction *hashAct = new QAction( hashIcon, tr("&Hash"), this );
    hashAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_D));
    connect( hashAct, &QAction::triggered, this, &MainWindow::hash );
    hashAct->setStatusTip(tr("Generate hash value" ));
    cryptMenu->addAction( hashAct );
    cryptToolBar->addAction( hashAct );

    const QIcon macIcon = QIcon::fromTheme("MAC", QIcon(":/images/mac.png"));
    QAction *macAct = new QAction( macIcon, tr("M&AC"), this );
    macAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M));
    connect( macAct, &QAction::triggered, this, &MainWindow::mac );
    macAct->setStatusTip(tr("Generate MAC value" ));
    cryptMenu->addAction( macAct );
    cryptToolBar->addAction( macAct );

    const QIcon encIcon = QIcon::fromTheme("Encrypt_Decrypt", QIcon(":/images/enc.png"));
    QAction *encDecAct = new QAction( encIcon, tr("&Encrypt/Decrypt"), this );
    encDecAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_E));
    connect( encDecAct, &QAction::triggered, this, &MainWindow::encDec );
    encDecAct->setStatusTip(tr("Data encrypt decrypt" ));
    cryptMenu->addAction( encDecAct );
    cryptToolBar->addAction( encDecAct );

    const QIcon signIcon = QIcon::fromTheme("Sign/Verify", QIcon(":/images/sign.png"));
    QAction *signVerifyAct = new QAction( signIcon, tr("&Sign/Verify"), this );
    signVerifyAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_S));
    connect( signVerifyAct, &QAction::triggered, this, &MainWindow::signVerify );
    signVerifyAct->setStatusTip(tr("Data signature and verify" ));
    cryptMenu->addAction( signVerifyAct );
    cryptToolBar->addAction( signVerifyAct );

    const QIcon pubEncIcon = QIcon::fromTheme("PubKey Encrypt/Decrypt", QIcon(":/images/pub_enc.png"));
    QAction *pubEncDecAct = new QAction( pubEncIcon, tr("&PubKey Encrypt/Decrypt"), this );
    pubEncDecAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_P));
    connect( pubEncDecAct, &QAction::triggered, this, &MainWindow::pubEncDec );
    pubEncDecAct->setStatusTip(tr("Data PubKey encrypt decrypt" ));
    cryptMenu->addAction( pubEncDecAct );
    cryptToolBar->addAction( pubEncDecAct );

    const QIcon agreeIcon = QIcon::fromTheme("Key Agreement", QIcon(":/images/agree.png"));
    QAction *keyAgreeAct = new QAction( agreeIcon, tr("Key&Agreement"), this );
    keyAgreeAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_A));
    connect( keyAgreeAct, &QAction::triggered, this, &MainWindow::keyAgree );
    keyAgreeAct->setStatusTip(tr("Key Agreement" ));
    cryptMenu->addAction( keyAgreeAct );
    cryptToolBar->addAction( keyAgreeAct );


    const QIcon cmsIcon = QIcon::fromTheme("CMS", QIcon(":/images/cms.png"));
    QAction *cmsAct = new QAction( cmsIcon, tr("&CMS"), this );
    cmsAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_G));
    connect( cmsAct, &QAction::triggered, this, &MainWindow::cms );
    cmsAct->setStatusTip(tr("PKCS#7 Cryptographic Message Syntax" ));
    cryptMenu->addAction( cmsAct );
//    cryptToolBar->addAction( cmsAct );

    const QIcon sssIcon = QIcon::fromTheme("SSS", QIcon(":/images/sss.png"));
    QAction *sssAct = new QAction( sssIcon, tr("&SSS"), this );
    sssAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_R));
    connect( sssAct, &QAction::triggered, this, &MainWindow::sss );
    sssAct->setStatusTip(tr("Shamir Secret Sharing Scheme" ));
    cryptMenu->addAction( sssAct );
//    cryptToolBar->addAction( sssAct );

    const QIcon certPVDIcon = QIcon::fromTheme("Cert PathValidation", QIcon(":/images/cert_pvd.png"));
    QAction *certPVDAct = new QAction( certPVDIcon, tr( "Cert &PathValidation"), this );
    certPVDAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_T));
    connect( certPVDAct, &QAction::triggered, this, &MainWindow::certPVD );
    certPVDAct->setStatusTip(tr("Certificate Path Validation"));
    cryptMenu->addAction( certPVDAct );
    cryptToolBar->addAction( certPVDAct );

    const QIcon otpIcon = QIcon::fromTheme("OTP", QIcon(":/images/otp.png"));
    QAction *genOTPAct = new QAction( otpIcon, tr("&OTP generate"), this );
    genOTPAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_O));
    connect( genOTPAct, &QAction::triggered, this, &MainWindow::genOTP );
    genOTPAct->setStatusTip(tr("Generate OTP value" ));
    cryptMenu->addAction( genOTPAct );

    const QIcon vidIcon = QIcon::fromTheme("VID", QIcon(":/images/vid.png"));
    QAction *vidAct = new QAction( vidIcon, tr("&VID"), this );
    vidAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_I));
    connect( vidAct, &QAction::triggered, this, &MainWindow::VID );
    vidAct->setStatusTip(tr("Make and Verify VID" ));
    cryptMenu->addAction( vidAct );

    const QIcon calcIcon = QIcon::fromTheme("BN Calc", QIcon(":/images/bn_calc.png"));
    QAction *calcAct = new QAction( calcIcon, tr("&BN Calculator"), this );
    calcAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_B));
    connect( calcAct, &QAction::triggered, this, &MainWindow::BNCalc );
    calcAct->setStatusTip(tr("Big Num Calculator" ));
    cryptMenu->addAction( calcAct );
    cryptToolBar->addAction( calcAct );

    const QIcon keyPairIcon = QIcon::fromTheme("KeyPair Manage", QIcon(":/images/keypair.png"));
    QAction *keyPairManAct = new QAction( keyPairIcon, tr( "KeyPairManage" ), this );
    keyPairManAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_Y ));
    connect( keyPairManAct, &QAction::triggered, this, &MainWindow::keyPairMan );
    keyPairManAct->setStatusTip( tr( "Key Pair Manage" ));
    cryptMenu->addAction( keyPairManAct );
    cryptToolBar->addAction( keyPairManAct );

    const QIcon certManIcon = QIcon::fromTheme("Certificate Manage", QIcon(":/images/cert.png"));
    QAction *certManAct = new QAction( certManIcon, tr( "Certificate Manage" ), this );
    certManAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M ));
    connect( certManAct, &QAction::triggered, this, &MainWindow::certMan );
    certManAct->setStatusTip( tr( "Certificate Manage" ));
    cryptMenu->addAction( certManAct );
    cryptToolBar->addAction( certManAct );

    const QIcon cavpIcon = QIcon::fromTheme( "tool-cavp", QIcon(":/images/cavp.png"));
    QAction *cavpAct = new QAction(cavpIcon, tr("&CAVP"), this);
    cavpAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_F));
    connect( cavpAct, &QAction::triggered, this, &MainWindow::CAVP );
    cavpAct->setStatusTip(tr("CAVP Test"));
    cryptMenu->addAction( cavpAct );

    const QIcon sslIcon = QIcon::fromTheme( "tool-ssl", QIcon(":/images/ssl.png"));
    QAction *sslAct = new QAction(sslIcon, tr("&SSL Verify"), this);
    sslAct->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_V));
    connect( sslAct, &QAction::triggered, this, &MainWindow::sslVerify );
    cavpAct->setStatusTip(tr("SSL Verify"));
    cryptMenu->addAction( sslAct );
    cryptToolBar->addAction( sslAct );

    if( berApplet->isLicense() == false )
    {
        keyManAct->setEnabled( false );
        hashAct->setEnabled( false );
        macAct->setEnabled( false );
        encDecAct->setEnabled( false );
        signVerifyAct->setEnabled( false );
        pubEncDecAct->setEnabled( false );
        keyAgreeAct->setEnabled( false );
        cmsAct->setEnabled( false );
        sssAct->setEnabled( false );
        certPVDAct->setEnabled( false );
        genOTPAct->setEnabled( false );
        vidAct->setEnabled( false );
        calcAct->setEnabled( false );
        keyPairManAct->setEnabled( false );
        cavpAct->setEnabled( false );
        sslAct->setEnabled( false );
    }


    QMenu *protoMenu = menuBar()->addMenu( tr("&Protocol" ));
//    QToolBar *protoToolBar = addToolBar( tr( "Protocol" ));
//    protoToolBar->setIconSize( QSize(nWidth,nHeight));
//    protoToolBar->layout()->setSpacing(nSpacing);

    const QIcon ocspIcon = QIcon::fromTheme( "ocsp_client", QIcon(":/images/ocsp.png"));
    QAction *ocspAct = new QAction( ocspIcon, tr( "&OCSP client"), this );
    ocspAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_S));
    connect( ocspAct, &QAction::triggered, this, &MainWindow::ocspClient );
    protoMenu->addAction( ocspAct );

    const QIcon tspIcon = QIcon::fromTheme( "tsp_client", QIcon(":/images/tsp.png"));
    QAction *tspAct = new QAction( tspIcon, tr( "&TSP client"), this );
    tspAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_T));
    connect( tspAct, &QAction::triggered, this, &MainWindow::tspClient );
    protoMenu->addAction( tspAct );

    const QIcon cmpIcon = QIcon::fromTheme( "cmp_client", QIcon(":/images/cmp.png"));
    QAction *cmpAct = new QAction( cmpIcon, tr( "&CMP client"), this );
    cmpAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_C));
    connect( cmpAct, &QAction::triggered, this, &MainWindow::cmpClient );
    protoMenu->addAction( cmpAct );

    const QIcon scepIcon = QIcon::fromTheme( "scep_client", QIcon(":/images/scep.png"));
    QAction *scepAct = new QAction( scepIcon, tr( "&SCEP client"), this );
    scepAct->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_S));
    connect( scepAct, &QAction::triggered, this, &MainWindow::scepClient );
    protoMenu->addAction( scepAct );

    if( berApplet->isLicense() == false )
    {
        ocspAct->setEnabled( false );
        tspAct->setEnabled( false );
        cmpAct->setEnabled( false );
        scepAct->setEnabled( false );
    }

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    helpToolBar->setIconSize( QSize(nWidth,nHeight));
    helpToolBar->layout()->setSpacing(nSpacing);

    const QIcon settingIcon = QIcon::fromTheme("berview-help", QIcon(":/images/setting.png"));
    QAction *settingAct = new QAction( settingIcon, tr("&Settings"), this );
    connect( settingAct, &QAction::triggered, this, &MainWindow::setting );
    settingAct->setStatusTip(tr("Set the variable"));
    helpMenu->addAction( settingAct );
 //   helpToolBar->addAction( settingAct );

    const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
    QAction *clearAct = new QAction( clearIcon, tr("&Clear Log"), this );
    connect( clearAct, &QAction::triggered, this, &MainWindow::clearLog );
    clearAct->setShortcut( QKeySequence(Qt::Key_F9));
    clearAct->setStatusTip(tr("clear information and log"));
    helpMenu->addAction( clearAct );
    helpToolBar->addAction( clearAct );

    QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_halt.png" ));
    QAction *logAct = new QAction( logIcon, tr( "&Log Halt" ), this );
    connect( logAct, &QAction::triggered, this, &MainWindow::toggleLog );
    logAct->setShortcut( QKeySequence(Qt::Key_F10));
    logAct->setCheckable(true);
    logAct->setStatusTip( tr( "Log Halt" ));
    helpMenu->addAction( logAct );
    helpToolBar->addAction( logAct );

    if( berApplet->isLicense() == false )
    {
        clearAct->setEnabled( false );
        logAct->setEnabled( false );
    }

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    QAction *lcnAct = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcnAct, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcnAct );
    lcnAct->setStatusTip(tr("License Information"));

    const QIcon aboutIcon = QIcon::fromTheme("berview-icon", QIcon(":/images/bereditor.png"));

    QAction *bugIssueAct = new QAction( aboutIcon, tr("Bug or Issue Report"), this);
    connect( bugIssueAct, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bugIssueAct );
    bugIssueAct->setStatusTip(tr("Bug or Issue Report"));

    QAction *qnaAct = new QAction( aboutIcon, tr("Q and A"), this);
    connect( qnaAct, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qnaAct );
    qnaAct->setStatusTip(tr("Question and Answer"));

    QAction *aboutAct = new QAction( aboutIcon, tr("&About BerEditor"), this );
    connect( aboutAct, &QAction::triggered, this, &MainWindow::about );
    aboutAct->setShortcut( QKeySequence(Qt::Key_F1));
    aboutAct->setStatusTip(tr("Show the BerEditor"));
    helpMenu->addAction( aboutAct );
    helpToolBar->addAction( aboutAct );

    menuBar()->show();
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createCryptoDlg()
{
    key_man_dlg_ = new KeyManDlg;
    gen_hash_dlg_ = new GenHashDlg;
    gen_mac_dlg_ = new GenMacDlg;
    enc_dec_dlg_ = new EncDecDlg;
    sign_verify_dlg_ = new SignVerifyDlg;
    pub_enc_dec_dlg_ = new PubEncDecDlg;
    key_agree_dlg_ = new KeyAgreeDlg;
    cms_dlg_ = new CMSDlg;
    sss_dlg_ = new SSSDlg;
    cert_pvd_dlg_ = new CertPVDDlg;
    gen_otp_dlg_ = new GenOTPDlg;
    cavp_dlg_ = new CAVPDlg;
    ssl_verify_dlg_ = new SSLVerifyDlg;
    vid_dlg_ = new VIDDlg;
    bn_calc_dlg_ = new BNCalcDlg;
    key_pair_man_dlg_ = new KeyPairManDlg;
    ocsp_client_dlg_ = new OCSPClientDlg;
    tsp_client_dlg_ = new TSPClientDlg;
    cmp_client_dlg_ = new CMPClientDlg;
    scep_client_dlg_ = new SCEPClientDlg;
    cert_man_dlg_ = new CertManDlg;
}

void MainWindow::newFile()
{
    QString cmd = berApplet->cmd();
    QProcess *process = new QProcess();
    process->setProgram( berApplet->cmd() );
    process->start();
}

void MainWindow::insertBER()
{
    int ret = 0;

    InsertBerDlg insertBerDlg;
    ret = insertBerDlg.exec();

    if( ret == QDialog::Accepted )
    {
        BIN binData = {0,0};
        QString strData = insertBerDlg.getData();

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
        decodeData( &binData, "Unknown" );
        JS_BIN_reset( &binData );
    }
}

void MainWindow::insertData()
{
    int ret = -1;

    InsertDataDlg insData(this);
    ret = insData.exec();
}

void MainWindow::numTrans()
{
    NumTransDlg numTransDlg;
    numTransDlg.exec();
}

void MainWindow::open()
{
    QString strPath = berApplet->getBERPath();
    QString fileName = findFile( this, JS_FILE_TYPE_BER, strPath );

    if( !fileName.isEmpty() )
    {
        if( berFileOpen(fileName) != 0 ) return;

        berApplet->setBERPath( fileName );
    }
}

void MainWindow::openRecent()
{
    int ret = 0;
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
    {
        ret = berFileOpen( action->data().toString() );
        if( ret != 0 ) return;

        berApplet->setBERPath( action->data().toString() );
    }
}

void MainWindow::openCert()
{
    QString strPath = berApplet->curFile();

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    BIN binCert = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCert );

    if( JS_PKI_isCert( &binCert ) == 1 )
    {
        CertInfoDlg certInfo;
//        certInfo.setCertBIN( &binCert );
        certInfo.setCertPath( fileName );
        certInfo.exec();
        berApplet->setCurFile( fileName );
    }
    else
    {
        bool bVal = true;
        if( JS_PKI_isCRL( &binCert ) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CRL. Open it as CRL information?"), this, true );
            if( bVal == true )
            {
                CRLInfoDlg crlInfo;
 //               crlInfo.setCRL_BIN( &binCert );
                crlInfo.setCRLPath( fileName );
                crlInfo.exec();
            }
        }
        else if( JS_PKI_isCSR( &binCert ) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CSR. Open it as CSR information?"), this, true );
            if( bVal == true )
            {
                CSRInfoDlg csrInfo;
//                csrInfo.setReqBIN( &binCert );
                csrInfo.setReqPath( fileName );
                csrInfo.exec();
            }
        }
        else
        {
            berApplet->warningBox( tr( "Invalid certificate file"), this );
        }
    }

end :
    JS_BIN_reset( &binCert );
}

void MainWindow::openCRL()
{
    QString strPath = berApplet->curFile();

    QString fileName = findFile( this, JS_FILE_TYPE_CRL, strPath );
    BIN binCRL = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCRL );

    if( JS_PKI_isCRL( &binCRL ) == 1 )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &binCRL );
        crlInfo.exec();

        berApplet->setCurFile( fileName );
    }
    else
    {
        bool bVal = true;
        if( JS_PKI_isCert( &binCRL ) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is certificate. Open it as certificate information?"), this, true );
            if( bVal == true )
            {
                CertInfoDlg certInfo;
                certInfo.setCertBIN( &binCRL );
                certInfo.exec();
            }
        }
        else if( JS_PKI_isCSR( &binCRL) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CSR. Open it as CSR information?"), this, true );
            if( bVal == true )
            {
                CSRInfoDlg csrInfo;
                csrInfo.setReqBIN( &binCRL );
                csrInfo.exec();
            }
        }
        else
        {
            berApplet->warningBox( tr( "Invalid CRL file"), this );
        }
    }

    JS_BIN_reset( &binCRL );
}

void MainWindow::openCSR()
{
    QString strPath = berApplet->curFile();

    QString fileName = findFile( this, JS_FILE_TYPE_CSR, strPath );
    BIN binCSR = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCSR );

    if( JS_PKI_isCSR( &binCSR ) == 1 )
    {
        CSRInfoDlg csrInfo;
        csrInfo.setReqBIN( &binCSR );
        csrInfo.exec();

        berApplet->setCurFile( fileName );
    }
    else
    {
        bool bVal = true;
        if( JS_PKI_isCert( &binCSR ) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is certificate. Open it as certificate information?"), this, true );
            if( bVal == true )
            {
                CertInfoDlg certInfo;
                certInfo.setCertBIN( &binCSR );
                certInfo.exec();
            }
        }
        else if( JS_PKI_isCRL( &binCSR) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CRL. Open it as CRL information?"), this, true );
            if( bVal == true )
            {
                CRLInfoDlg crlInfo;
                crlInfo.setCRL_BIN( &binCSR );
                crlInfo.exec();
            }
        }
        else
        {
            berApplet->warningBox( tr( "Invalid CSR file"), this );
        }
    }

    JS_BIN_reset( &binCSR );
}

void MainWindow::openBer( const BIN *pBer )
{
    ber_model_->setBer( pBer );
    ber_model_->parseTree();

    left_tree_->header()->setVisible(false);
    left_tree_->viewRoot();
    QModelIndex ri = ber_model_->index(0,0);
    left_tree_->expand(ri);

    if( berApplet->isLicense() )
    {
        left_tree_->showTextView();
        left_tree_->showXMLView();
    }
}

bool MainWindow::isChanged()
{
    BIN& binBer = ber_model_->getBer();

    if( binBer.nLen > 0 )
    {
        BIN binFile = {0,0};

        if( file_path_.length() < 1 )
            return true;

        JS_BIN_fileReadBER( file_path_.toLocal8Bit().toStdString().c_str(), &binFile );
        if( JS_BIN_cmp( &binBer, &binFile ) != 0 )
        {
            JS_BIN_reset( &binFile );
            return true;
        }

        JS_BIN_reset( &binFile );
    }

    return false;
}

void MainWindow::log( const QString strLog, QColor cr )
{
    if( log_halt_ == true ) return;    
    if( text_tab_->isTabEnabled( 1 ) == false ) return;

    QTextCursor cursor = log_text_->textCursor();
//    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.insertText( "\n" );

    log_text_->setTextCursor( cursor );
    log_text_->repaint();
}

void MainWindow::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

void MainWindow::info( const QString strLog, QColor cr )
{
    QTextCursor cursor = info_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );

    info_text_->setTextCursor( cursor );
    info_text_->repaint();
}

QString MainWindow::getInfo()
{
    return info_text_->toPlainText();
}

int MainWindow::berFileOpen(const QString berPath)
{
    BIN binRead = {0,0};

    int ret = JS_BIN_fileReadBER( berPath.toLocal8Bit().toStdString().c_str(), &binRead );

    if( ret > 0 )
    {
        openBer( &binRead );
        JS_BIN_reset( &binRead );

        file_path_ = berPath;
        adjustForCurrentFile( berPath );
        setTitle( berPath );
    }

    return 0;
}

void MainWindow::setTitle( const QString strName )
{
    QString strTitle = berApplet->getBrand();

    if( berApplet->isLicense() == false )
        strTitle += " (Unlicensed version)";

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

   setWindowTitle( strTitle );
}

void MainWindow::showTextMsg(const QString &msg)
{
    log_text_->setText( msg );
}

void MainWindow::adjustForCurrentFile( const QString& filePath )
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    recentFilePaths.removeAll( filePath );
    recentFilePaths.prepend( filePath );

    while( recentFilePaths.size() > kMaxRecentFiles )
        recentFilePaths.removeLast();

    settings.setValue( "recentFiles", recentFilePaths );

    updateRecentActionList();
}

void MainWindow::updateRecentActionList()
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    auto itEnd = 0u;

    if( recentFilePaths.size() <= kMaxRecentFiles )
        itEnd = recentFilePaths.size();
    else
        itEnd = kMaxRecentFiles;

    for( auto i = 0u; i < itEnd; ++i )
    {
        QString strippedName = QString( "%1 ").arg(i);
        strippedName += QFileInfo(recentFilePaths.at(i)).fileName();

        recent_file_list_.at(i)->setText(strippedName);
        recent_file_list_.at(i)->setData( recentFilePaths.at(i));
        recent_file_list_.at(i)->setVisible(true);
    }

    for( auto i = itEnd; i < kMaxRecentFiles; ++i )
        recent_file_list_.at(i)->setVisible(false);
}


void MainWindow::about()
{
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

void MainWindow::keyManage()
{
    key_man_dlg_->show();
    key_man_dlg_->raise();
    key_man_dlg_->activateWindow();
}

void MainWindow::hash()
{
    gen_hash_dlg_->show();
    gen_hash_dlg_->raise();
    gen_hash_dlg_->activateWindow();
}

void MainWindow::mac()
{    
    gen_mac_dlg_->show();
    gen_mac_dlg_->raise();
    gen_mac_dlg_->activateWindow();
}

void MainWindow::keyAgree()
{
    key_agree_dlg_->show();
    key_agree_dlg_->raise();
    key_agree_dlg_->activateWindow();
}

void MainWindow::oidInfo()
{
    OIDInfoDlg oidInfoDlg;
    oidInfoDlg.exec();
}

void MainWindow::encDec()
{
    enc_dec_dlg_->show();
    enc_dec_dlg_->raise();
    enc_dec_dlg_->activateWindow();
}

void MainWindow::signVerify()
{
    sign_verify_dlg_->show();
    sign_verify_dlg_->raise();
    sign_verify_dlg_->activateWindow();
}

void MainWindow::pubEncDec()
{
    pub_enc_dec_dlg_->show();
    pub_enc_dec_dlg_->raise();
    pub_enc_dec_dlg_->activateWindow();
}

void MainWindow::cms()
{
    cms_dlg_->show();
    cms_dlg_->raise();
    cms_dlg_->activateWindow();
}

void MainWindow::sss()
{
    sss_dlg_->show();
    sss_dlg_->raise();
    sss_dlg_->activateWindow();
}

void MainWindow::certPVD()
{
    cert_pvd_dlg_->show();
    cert_pvd_dlg_->raise();
    cert_pvd_dlg_->activateWindow();
}

void MainWindow::CAVP()
{
    cavp_dlg_->show();
    cavp_dlg_->raise();
    cavp_dlg_->activateWindow();
}

void MainWindow::sslVerify()
{
    ssl_verify_dlg_->show();
    ssl_verify_dlg_->raise();
    ssl_verify_dlg_->activateWindow();
}

void MainWindow::genOTP()
{
    gen_otp_dlg_->show();
    gen_otp_dlg_->raise();
    gen_otp_dlg_->activateWindow();
}

void MainWindow::VID()
{
    vid_dlg_->show();
    vid_dlg_->raise();
    vid_dlg_->activateWindow();
}

void MainWindow::BNCalc()
{
    bn_calc_dlg_->show();
    bn_calc_dlg_->raise();
    bn_calc_dlg_->activateWindow();
}

void MainWindow::keyPairMan()
{
    key_pair_man_dlg_->show();
    key_pair_man_dlg_->raise();
    key_pair_man_dlg_->activateWindow();
}

void MainWindow::ocspClient()
{
    ocsp_client_dlg_->show();
    ocsp_client_dlg_->raise();
    ocsp_client_dlg_->activateWindow();
}

void MainWindow::tspClient()
{
    tsp_client_dlg_->show();
    tsp_client_dlg_->raise();
    tsp_client_dlg_->activateWindow();
}

void MainWindow::cmpClient()
{
    cmp_client_dlg_->show();
    cmp_client_dlg_->raise();
    cmp_client_dlg_->activateWindow();
}

void MainWindow::scepClient()
{
    scep_client_dlg_->show();
    scep_client_dlg_->raise();
    scep_client_dlg_->activateWindow();
}

void MainWindow::certMan()
{
    cert_man_dlg_->setMode( ManModeBase );
    cert_man_dlg_->setTitle( tr( "Certificate Management" ));
    cert_man_dlg_->show();
    cert_man_dlg_->raise();
    cert_man_dlg_->activateWindow();
}

void MainWindow::getURI()
{
    GetURIDlg getURIDlg;
    getURIDlg.exec();
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

void MainWindow::closeEvent(QCloseEvent *event)
{
    if( isChanged() )
    {
        QString strMsg = tr("Do you want to save the file in DER format?\n[The Source is PEM or The Source DER changed]");
        bool bVal = berApplet->yesOrNoBox( strMsg, this, false );
        if( bVal ) saveAs();
    }

    exit(0);
}

void MainWindow::rightTableCustomMenu( const QPoint& pos )
{
    QMenu *menu = new QMenu(this);

    QAction *copyAct = new QAction( tr("Copy" ), this );
    connect( copyAct, SIGNAL(triggered()), this, SLOT(rightTableCopy()));

    QAction *selAllAct = new QAction( tr("Select All"), this );
    connect( selAllAct, SIGNAL(triggered()), this, SLOT(rightTableSelectAll()));

    QAction *unSelAllAct = new QAction( tr( "Unselect All" ), this );
    connect( unSelAllAct, SIGNAL(triggered()), this, SLOT(rightTableUnselectAll()));

    menu->addAction( copyAct );
    menu->addAction( selAllAct );
    menu->addAction( unSelAllAct );

    menu->popup(right_table_->viewport()->mapToGlobal(pos));
}

bool rowColSort( const QTableWidgetItem* item1, const QTableWidgetItem* item2 )
{
    int row1 = 0;
    int row2 = 0;

    row1 = item1->row();
    row2 = item2->row();

    if( row1 != row2 )
        return ( row1 < row2 );
    else
    {
        int col1 = item1->column();
        int col2 = item2->column();

        return ( col1 < col2 );
    }
}

void MainWindow::rightTableCopy()
{
    QString strText;
    QList<QTableWidgetItem *> items = right_table_->selectedItems();

//    qSort( items.begin(), items.end(), rowColSort );
    std::sort( items.begin(), items.end(), rowColSort );

    for( int i = 0; i < items.size(); i++ )
    {
        QString strHex = items.at(i)->text();
        strText += strHex;
    }

    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( strText );

    berApplet->log( QString("Copy Data:%1").arg( strText ));
}

void MainWindow::rightTableSelectAll()
{
//    right_table_->selectAll();
    for( int i = 1; i <= 16; i++ )
        right_table_->selectColumn(i);
}

void MainWindow::rightTableUnselectAll()
{
    right_table_->clearSelection();
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
        JS_BIN_fileWrite( &binBer, file_path_.toLocal8Bit().toStdString().c_str() );
    }
}

void MainWindow::saveAs()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    strFilter = tr("BIN Files (*.ber *.der);;All Files (*.*)");

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Save As..."),
                                                     file_path_,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 )
    {
        BIN& binBer = ber_model_->getBer();
        JS_BIN_fileWrite( &binBer, fileName.toLocal8Bit().toStdString().c_str() );
    }
}

void MainWindow::clearLog()
{
    log_text_->clear();
//    info_text_->clear();
}

void MainWindow::toggleLog()
{
    if( log_halt_ == true )
    {
        log_halt_ = false;
        log( "Log is enable" );
    }
    else
    {
        log( "Log is halt" );
        log_halt_ = true;
    }
}

void MainWindow::licenseInfo()
{
    LCNInfoDlg lcnInfoDlg;
    if( lcnInfoDlg.exec() == QDialog::Accepted )
    {
//        if( berApplet->yesOrNoBox(tr("The license has been changed. Restart to apply it?"), this, true))
//            berApplet->restartApp();
    }
}

void MainWindow::bugIssueReport()
{
    QString link = "https://github.com/jykim74/BerEditor/issues/new";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::qnaDiscussion()
{
//    QString link = "https://github.com/jykim74/BerEditor/discussions/new?category=q-a";
    QString link = "https://groups.google.com/g/bereditor";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::useLog( bool bEnable )
{
    text_tab_->setTabEnabled( 1, bEnable );
}

void MainWindow::decodeData( const BIN *pData, const QString strPath )
{
    if( pData == NULL || pData->nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no data"), this );
        return;
    }

    openBer( pData );
    file_path_ = strPath;
    setTitle( QString( strPath ));
}

void MainWindow::print()
{
#if QT_CONFIG(printdialog)
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog *dlg = new QPrintDialog(&printer, this);

    if (log_text_->textCursor().hasSelection())
#if QT_VERSION >= 0x060000
        dlg->setOptions(QAbstractPrintDialog::PrintSelection);
#else
        dlg->addEnabledOption(QAbstractPrintDialog::PrintSelection);
#endif

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
//    exit(0);
//    close();
    berApplet->exitApp();
}
