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
#include "common.h"

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
 //   right_table_->setSelectionMode( QAbstractItemView::ExtendedSelection );
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

    if( berApplet->isLicense() )
    {
        right_xml_ = new QTextEdit;
        right_xml_->setReadOnly(true);

        table_tab_->addTab( right_xml_, tr( "XML" ));
        right_text_ = new QTextEdit;
        right_text_->setReadOnly(true);

        table_tab_->addTab( right_text_, tr( "Text" ));
    }

    vsplitter_->addWidget( table_tab_ );

    text_tab_ = new QTabWidget;
    vsplitter_->addWidget( text_tab_ );
    text_tab_->setTabPosition( QTabWidget::South );
    text_tab_->addTab( info_text_, tr("information") );

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList<int> sizes;

#ifdef Q_OS_MAC
    sizes << 540 << 1200;
#else
    sizes << 400 << 1200;
#endif

    hsplitter_->setSizes(sizes);

#ifdef Q_OS_MAC
    resize( 1040, 780 );
#else
    resize( 1020, 760 );
#endif

    setCentralWidget(hsplitter_);
    createTableMenu();
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
    right_table_->setColumnWidth(0, 80);
#else
#ifdef Q_OS_LINUX
    right_table_->setColumnWidth(0, 100);
#else
    right_table_->setColumnWidth(0, 90);
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
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

#ifdef Q_OS_MAC
    fileToolBar->setIconSize( QSize(24,24));
    fileToolBar->layout()->setSpacing(0);
#endif

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
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction(quitAct);

    QMenu *editMenu = menuBar()->addMenu(tr("&Edit"));
    QToolBar *editToolBar = addToolBar(tr("Edit"));

#ifdef Q_OS_MAC
    editToolBar->setIconSize( QSize(24,24));
    editToolBar->layout()->setSpacing(0);
#endif

    const QIcon copyIcon = QIcon::fromTheme("edit-copy", QIcon(":/images/copy.png"));
    QAction *copyAct = new QAction(copyIcon, tr("&Copy Information"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the current selection's contents to the clipboard"));
    connect( copyAct, &QAction::triggered, left_tree_, &BerTreeView::copy );
    editMenu->addAction(copyAct);
//    editToolBar->addAction(copyAct);

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

    QMenu *toolMenu = menuBar()->addMenu(tr("&Tool"));
    QToolBar *toolToolBar = addToolBar(tr("Tool"));

#ifdef Q_OS_MAC
    toolToolBar->setIconSize( QSize(24,24));
    toolToolBar->layout()->setSpacing(0);
#endif

    const QIcon dataTransIcon = QIcon::fromTheme("data-trans", QIcon(":/images/data_trans.png"));
    QAction *dataEncodeAct = new QAction( dataTransIcon, tr("Data&Encoder"), this );
    connect( dataEncodeAct, &QAction::triggered, this, &MainWindow::dataEncoder );
    dataEncodeAct->setStatusTip(tr("This is tool for encoding data" ));
    toolMenu->addAction( dataEncodeAct );
    toolToolBar->addAction( dataEncodeAct );

    const QIcon numTransIcon = QIcon::fromTheme("number-trans", QIcon(":/images/two.png"));
    QAction *numTransAct = new QAction( numTransIcon, tr("&NumTrans"), this);
    connect( numTransAct, &QAction::triggered, this, &MainWindow::numTrans );
    numTransAct->setStatusTip(tr("Number transmission" ));
    toolMenu->addAction( numTransAct );
    toolToolBar->addAction( numTransAct );

    const QIcon oidIcon = QIcon::fromTheme("tool-oid", QIcon(":/images/oid.png"));
    QAction *oidAct = new QAction(oidIcon, tr("&OID Information"), this);
    connect( oidAct, &QAction::triggered, this, &MainWindow::oidInfo );
    oidAct->setStatusTip(tr("Show OID information"));
    toolMenu->addAction( oidAct );
    toolToolBar->addAction( oidAct );

    if( berApplet->isLicense() )
    {
        const QIcon berIcon = QIcon::fromTheme("ber-insert", QIcon(":/images/ber.png"));
        QAction *insertBerAct = new QAction(berIcon, tr("Insert &BER"), this);
        connect( insertBerAct, &QAction::triggered, this, &MainWindow::insertBER );
        insertBerAct->setStatusTip(tr("Insert BER record"));
        toolMenu->addAction( insertBerAct );
        toolToolBar->addAction( insertBerAct );
    }

    const QIcon insertIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/insert.png"));
    QAction *insertDataAct = new QAction(insertIcon, tr("&Insert Data"), this);
    connect( insertDataAct, &QAction::triggered, this, &MainWindow::insertData );
    insertDataAct->setStatusTip(tr("Insert ber data"));
    toolMenu->addAction( insertDataAct );
    toolToolBar->addAction( insertDataAct );

    const QIcon uriIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/uri.png"));
    QAction *getURIAct = new QAction(uriIcon, tr("&Get URI data"), this);
    connect( getURIAct, &QAction::triggered, this, &MainWindow::getURI );
    getURIAct->setStatusTip(tr("Get Ber data from URI"));
    toolMenu->addAction( getURIAct );
    toolToolBar->addAction( getURIAct );

    menuBar()->addSeparator();

    if( berApplet->isLicense() )
    {
        QMenu *cryptMenu = menuBar()->addMenu(tr("&Cryptogram"));
        QToolBar *cryptToolBar = addToolBar( "Cryptogram" );

#ifdef Q_OS_MAC
        cryptToolBar->setIconSize( QSize(24,24));
        cryptToolBar->layout()->setSpacing(0);
#endif

        const QIcon keyIcon = QIcon::fromTheme("key-man", QIcon(":/images/key.png"));
        QAction *keyManAct = new QAction( keyIcon, tr("&KeyManage"), this );
        connect( keyManAct, &QAction::triggered, this, &MainWindow::keyManage );
        keyManAct->setStatusTip(tr("Key Manage function" ));
        cryptMenu->addAction( keyManAct );
        cryptToolBar->addAction( keyManAct );

        const QIcon hashIcon = QIcon::fromTheme("Hash", QIcon(":/images/hash.png"));
        QAction *hashAct = new QAction( hashIcon, tr("&Hash"), this );
        connect( hashAct, &QAction::triggered, this, &MainWindow::hash );
        hashAct->setStatusTip(tr("Generate hash value" ));
        cryptMenu->addAction( hashAct );
        cryptToolBar->addAction( hashAct );

        const QIcon macIcon = QIcon::fromTheme("MAC", QIcon(":/images/mac.png"));
        QAction *macAct = new QAction( macIcon, tr("M&AC"), this );
        connect( macAct, &QAction::triggered, this, &MainWindow::mac );
        macAct->setStatusTip(tr("Generate MAC value" ));
        cryptMenu->addAction( macAct );
        cryptToolBar->addAction( macAct );

        const QIcon encIcon = QIcon::fromTheme("Encrypt_Decrypt", QIcon(":/images/enc.png"));
        QAction *encDecAct = new QAction( encIcon, tr("&Encrypt/Decrypt"), this );
        connect( encDecAct, &QAction::triggered, this, &MainWindow::encDec );
        encDecAct->setStatusTip(tr("Data encrypt decrypt" ));
        cryptMenu->addAction( encDecAct );
        cryptToolBar->addAction( encDecAct );

        const QIcon signIcon = QIcon::fromTheme("Sign/Verify", QIcon(":/images/sign.png"));
        QAction *signVerifyAct = new QAction( signIcon, tr("&Sign/Verify"), this );
        connect( signVerifyAct, &QAction::triggered, this, &MainWindow::signVerify );
        signVerifyAct->setStatusTip(tr("Data signature and verify" ));
        cryptMenu->addAction( signVerifyAct );
        cryptToolBar->addAction( signVerifyAct );

        const QIcon pubEncIcon = QIcon::fromTheme("PubKey Encrypt/Decrypt", QIcon(":/images/pub_enc.png"));
        QAction *pubEncDecAct = new QAction( pubEncIcon, tr("&PubKey Encrypt/Decrypt"), this );
        connect( pubEncDecAct, &QAction::triggered, this, &MainWindow::pubEncDec );
        pubEncDecAct->setStatusTip(tr("Data PubKey encrypt decrypt" ));
        cryptMenu->addAction( pubEncDecAct );
        cryptToolBar->addAction( pubEncDecAct );

        const QIcon agreeIcon = QIcon::fromTheme("Key Agreement", QIcon(":/images/agree.png"));
        QAction *keyAgreeAct = new QAction( agreeIcon, tr("Key&Agreement"), this );
        connect( keyAgreeAct, &QAction::triggered, this, &MainWindow::keyAgree );
        keyAgreeAct->setStatusTip(tr("Key Agreement" ));
        cryptMenu->addAction( keyAgreeAct );
        cryptToolBar->addAction( keyAgreeAct );


        const QIcon cmsIcon = QIcon::fromTheme("CMS", QIcon(":/images/cms.png"));
        QAction *cmsAct = new QAction( cmsIcon, tr("&CMS"), this );
        connect( cmsAct, &QAction::triggered, this, &MainWindow::cms );
        cmsAct->setStatusTip(tr("PKCS#7 Cryptographic Message Syntax" ));
        cryptMenu->addAction( cmsAct );
        cryptToolBar->addAction( cmsAct );

        const QIcon sssIcon = QIcon::fromTheme("SSS", QIcon(":/images/sss.png"));
        QAction *sssAct = new QAction( sssIcon, tr("&SSS"), this );
        connect( sssAct, &QAction::triggered, this, &MainWindow::sss );
        sssAct->setStatusTip(tr("Shamir Secret Sharing Scheme" ));
        cryptMenu->addAction( sssAct );
        cryptToolBar->addAction( sssAct );

        const QIcon certPVDIcon = QIcon::fromTheme("Cert PathValidation", QIcon(":/images/cert_pvd.png"));
        QAction *certPVDAct = new QAction( certPVDIcon, tr( "Cert &PathValidation"), this );
        connect( certPVDAct, &QAction::triggered, this, &MainWindow::certPVD );
        certPVDAct->setStatusTip(tr("Certificate Path Validation"));
        cryptMenu->addAction( certPVDAct );
        cryptToolBar->addAction( certPVDAct );

        const QIcon otpIcon = QIcon::fromTheme("OTP", QIcon(":/images/otp.png"));
        QAction *genOTPAct = new QAction( otpIcon, tr("&OTP generate"), this );
        connect( genOTPAct, &QAction::triggered, this, &MainWindow::genOTP );
        genOTPAct->setStatusTip(tr("Generate OTP value" ));
        cryptMenu->addAction( genOTPAct );
//      cryptToolBar->addAction( genOTPAct );

        const QIcon cavpIcon = QIcon::fromTheme( "tool-cavp", QIcon(":/images/cavp.png"));
        QAction *cavpAct = new QAction(cavpIcon, tr("&CAVP"), this);
        connect( cavpAct, &QAction::triggered, this, &MainWindow::CAVP );
        cavpAct->setStatusTip(tr("CAVP Test"));
        cryptMenu->addAction( cavpAct );
    //    cryptToolBar->addAction( cavpAct );
    }

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

#ifdef Q_OS_MAC
    helpToolBar->setIconSize( QSize(24,24));
    helpToolBar->layout()->setSpacing(0);
#endif

    const QIcon settingIcon = QIcon::fromTheme("berview-help", QIcon(":/images/setting.png"));
    QAction *settingAct = new QAction( settingIcon, tr("&Settings"), this );
    connect( settingAct, &QAction::triggered, this, &MainWindow::setting );
    settingAct->setStatusTip(tr("Set the variable"));
    helpMenu->addAction( settingAct );
    helpToolBar->addAction( settingAct );

    if( berApplet->isLicense() )
    {
        const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
        QAction *clearAct = new QAction( clearIcon, tr("&Clear Log"), this );
        connect( clearAct, &QAction::triggered, this, &MainWindow::clearLog );
        clearAct->setStatusTip(tr("clear information and log"));
        helpMenu->addAction( clearAct );
        helpToolBar->addAction( clearAct );

        QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_halt.png" ));
        QAction *logAct = new QAction( logIcon, tr( "&Log Halt" ), this );
        connect( logAct, &QAction::triggered, this, &MainWindow::toggleLog );
        logAct->setCheckable(true);
        logAct->setStatusTip( tr( "Log Halt" ));
        helpMenu->addAction( logAct );
        helpToolBar->addAction( logAct );
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
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
        berFileOpen( action->data().toString() );
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

        JS_BIN_fileRead( file_path_.toLocal8Bit().toStdString().c_str(), &binFile );
        if( JS_BIN_cmp( &binBer, &binFile ) != 0 )
        {
            JS_BIN_reset( &binFile );
            return true;
        }
    }

    return false;
}

void MainWindow::log( const QString strLog, QColor cr )
{
    if( log_halt_ == true ) return;

    if( text_tab_->count() <= 1 ) return;

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
        if( berApplet->isLicense() == false )
        {
            if( binRead.nLen > kNoLicenseLimitMaxSize )
            {
                QString strMsg = tr( "A BER size greater than 10000 bytes requires a license." );
                berApplet->warningBox( strMsg, this );
                return -1;
            }
        }

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
   QString strWinTitle = QString( "%1 - %2" ).arg( berApplet->getBrand() ).arg( strName );

   setWindowTitle( strWinTitle );
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

void MainWindow::genOTP()
{
    gen_otp_dlg_->show();
    gen_otp_dlg_->raise();
    gen_otp_dlg_->activateWindow();
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
        if( berApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            berApplet->restartApp();
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

void MainWindow::logView( bool bShow )
{
    if( bShow == true )
    {
        if( text_tab_->count() <= 1 )
            text_tab_->addTab( log_text_, tr("log") );
    }
    else
    {
        if( text_tab_->count() == 2 )
            text_tab_->removeTab(1);
    }
}

void MainWindow::decodeData( const BIN *pData, const QString strPath )
{
    if( pData == NULL || pData->nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no data"), this );
        return;
    }

    if( berApplet->isLicense() == false )
    {
        if( pData && pData->nLen > kNoLicenseLimitMaxSize )
        {
            QString strMsg = tr( "A BER size greater than 10000 bytes requires a license." );
            berApplet->warningBox( strMsg, this );
            return;
        }
    }

    openBer( pData );
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
