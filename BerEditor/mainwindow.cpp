/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QElapsedTimer>

#include "mainwindow.h"
// #include "ui_mainwindow.h"

#include "ber_model.h"
#include "ber_tree_view.h"

#include "decode_data_dlg.h"
#include "ber_applet.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "data_converter_dlg.h"
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
#include "num_converter_dlg.h"
#include "about_dlg.h"
#include "pkcs7_dlg.h"
#include "sss_dlg.h"
#include "cavp_dlg.h"
#include "make_ber_dlg.h"
#include "cert_pvd_dlg.h"
#include "lcn_info_dlg.h"
#include "ssl_check_dlg.h"
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
#include "acme_client_dlg.h"
#include "cert_man_dlg.h"
#include "common.h"
#include "decode_ttlv_dlg.h"
#include "ttlv_client_dlg.h"
#include "ttlv_encoder_dlg.h"
#include "make_ttlv_dlg.h"
#include "pri_key_info_dlg.h"
#include "cms_info_dlg.h"
#include "content_main.h"
#include "find_dlg.h"
#include "key_list_dlg.h"
#include "x509_compare_dlg.h"
#include "doc_signer_dlg.h"
#include "ber_check_dlg.h"

#include "js_pki_tools.h"
#include "js_kms.h"
#include "js_pkcs7.h"

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

#ifdef Q_OS_WINDOWS
static const int kColWidth = 26;
#else
static const int kColWidth = 28;
#endif

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    log_halt_ = false;

//    createCryptoDlg();
    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);
    setAcceptDrops(true);

#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
#endif

    initialize();
}

MainWindow::~MainWindow()
{
    recent_file_list_.clear();

    delete ber_model_;
    delete ttlv_model_;

    delete log_text_;
    delete info_text_;

    delete key_man_dlg_;
    delete gen_hash_dlg_;
    delete gen_mac_dlg_;
    delete enc_dec_dlg_;
    delete sign_verify_dlg_;
    delete pub_enc_dec_dlg_;
    delete key_agree_dlg_;
    delete pkcs7_dlg_;
    delete sss_dlg_;
    delete cert_pvd_dlg_;
    delete gen_otp_dlg_;
    delete cavp_dlg_;
    delete ssl_check_dlg_;
    delete vid_dlg_;
    delete bn_calc_dlg_;
    delete key_pair_man_dlg_;
    delete ocsp_client_dlg_;
    delete tsp_client_dlg_;
    delete cmp_client_dlg_;
    delete scep_client_dlg_;
    delete acme_client_dlg_;
    delete cert_man_dlg_;
    delete ttlv_encoder_dlg_;
    delete ttlv_client_dlg_;
    delete content_;
    delete find_dlg_;
    delete key_list_dlg_;
    delete x509_comp_dlg_;
    delete doc_signer_dlg_;

    delete table_tab_;
    delete text_tab_;

    delete vsplitter_;
    delete hsplitter_;
}

void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);

    ber_model_ = new BerModel(this);
    ttlv_model_ = new TTLVTreeModel(this);

    log_text_ = new QPlainTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new CodeEditor;
    info_text_->setReadOnly(true);

    right_table_ = new QTableWidget;
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    right_table_->setSelectionMode( QAbstractItemView::ExtendedSelection );
    right_table_->horizontalHeader()->setHighlightSections(false);
    right_table_->setStyleSheet( kSelectStyle );

//    right_table_->setSelectionMode(QAbstractItemView::ContiguousSelection);
//    right_table_->setSelectionMode(QAbstractItemView::MultiSelection);
//    right_table_->setSelectionMode(QAbstractItemView::SingleSelection);

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(rightTableCustomMenu(const QPoint&)));

    hsplitter_->addWidget(ber_model_->getTreeView());
    hsplitter_->addWidget(vsplitter_);

    table_tab_ = new QTabWidget;
    table_tab_->setTabPosition( QTabWidget::South );
    table_tab_->addTab( right_table_, tr( "Hex" ));

    right_xml_ = new CodeEditor;
    right_xml_->setReadOnly(true);
    table_tab_->addTab( right_xml_, tr( "XML" ));

    right_text_ = new CodeEditor;
    right_text_->setReadOnly(true);
    table_tab_->addTab( right_text_, tr( "Text" ));

    right_json_ = new CodeEditor;
    right_json_->setReadOnly(true);

#ifdef Q_OS_MACOS
    table_tab_->addTab( right_json_, tr("JSON ") );
#else
    table_tab_->addTab( right_json_, tr( "JSON" ));
#endif

    connect( table_tab_, SIGNAL(currentChanged(int)), this, SLOT(changeTableTab()));

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
        table_tab_->setTabEnabled( 3, false );

        text_tab_->setTabEnabled( 1, false );
    }

    createTableMenu();


    vsplitter_->setStretchFactor(0,2);
    vsplitter_->setStretchFactor(1,1);

    hsplitter_->setStretchFactor(1,3);

    setCentralWidget(hsplitter_);
    setTitle( "" );

#if 1
#ifdef Q_OS_WINDOWS
    resize( 900, 700 );
#else
    resize( 960, 700 );
#endif
#else
    table_tab_->setMinimumWidth( 700 );
    left_tree_->setMinimumWidth( 270 );
    left_tree_->setMinimumHeight( 600 );
    resize( minimumSizeHint().width(), minimumSizeHint().height() );
#endif
}

void MainWindow::createTableMenu()
{
    QStringList     labels = { tr("Address"), "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
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
        right_table_->setColumnWidth(i, kColWidth);

#ifdef Q_OS_MAC
    right_table_->setColumnWidth( 17, 100 );
#else
    right_table_->setColumnWidth( 17, 120 );
#endif

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

void MainWindow::createViewActions()
{
    bool bVal = false;
    QMenu *viewMenu = menuBar()->addMenu( tr("&View" ));

    QMenu *fileMenu = viewMenu->addMenu( tr("File ToolBar") );
    QMenu *editMenu = viewMenu->addMenu( tr("Edit ToolBar") );
    viewMenu->addSeparator();
    QMenu *toolMenu = viewMenu->addMenu( tr("Tool ToolBar" ));
    QMenu *cryptMenu = viewMenu->addMenu( tr( "Cryptography ToolBar"));
    QMenu *serviceMenu = viewMenu->addMenu( tr( "Service ToolBar"));
    QMenu *protoMenu = viewMenu->addMenu( tr( "Protocol ToolBar"));
    QMenu *kmipMenu = viewMenu->addMenu( tr( "KMIP ToolBar"));
    QMenu *helpMenu = viewMenu->addMenu( tr( "Help ToolBar" ));
    viewMenu->addSeparator();

    QAction *fileNewAct = new QAction( tr( "New"), this );
    bVal = isView( ACT_FILE_NEW );
    fileNewAct->setCheckable( true );
    fileNewAct->setChecked( bVal );
    connect( fileNewAct, &QAction::triggered, this, &MainWindow::viewFileNew );
    fileMenu->addAction( fileNewAct );

    QAction *fileOpenAct = new QAction( tr( "Open" ), this );
    bVal = isView( ACT_FILE_OPEN );
    fileOpenAct->setCheckable( true );
    fileOpenAct->setChecked( bVal );
    connect( fileOpenAct, &QAction::triggered, this, &MainWindow::viewFileOpen );
    fileMenu->addAction( fileOpenAct );

    QAction *fileOpenCertAct = new QAction( tr( "Open Certificate" ), this );
    bVal = isView( ACT_FILE_OPEN_CERT );
    fileOpenCertAct->setCheckable( true );
    fileOpenCertAct->setChecked( bVal );
    connect( fileOpenCertAct, &QAction::triggered, this, &MainWindow::viewFileOpenCert );
    fileMenu->addAction( fileOpenCertAct );

    QAction *fileOpenCRLAct = new QAction( tr( "Open CRL" ), this );
    bVal = isView( ACT_FILE_OPEN_CRL );
    fileOpenCRLAct->setCheckable( true );
    fileOpenCRLAct->setChecked( bVal );
    connect( fileOpenCRLAct, &QAction::triggered, this, &MainWindow::viewFileOpenCRL );
    fileMenu->addAction( fileOpenCRLAct );

    QAction *fileOpenCSRAct = new QAction( tr( "Open CSR" ), this );
    bVal = isView( ACT_FILE_OPEN_CSR );
    fileOpenCSRAct->setCheckable( true );
    fileOpenCSRAct->setChecked( bVal );
    connect( fileOpenCSRAct, &QAction::triggered, this, &MainWindow::viewFileOpenCSR );
    fileMenu->addAction( fileOpenCSRAct );

    QAction *fileOpenPriKeyAct = new QAction( tr( "Open PrivateKey" ), this );
    bVal = isView( ACT_FILE_OPEN_PRI_KEY );
    fileOpenPriKeyAct->setCheckable( true );
    fileOpenPriKeyAct->setChecked( bVal );
    connect( fileOpenPriKeyAct, &QAction::triggered, this, &MainWindow::viewFileOpenPriKey );
    fileMenu->addAction( fileOpenPriKeyAct );

    QAction *fileOpenPubKeyAct = new QAction( tr( "Open PublicKey" ), this );
    bVal = isView( ACT_FILE_OPEN_PUB_KEY );
    fileOpenPubKeyAct->setCheckable( true );
    fileOpenPubKeyAct->setChecked( bVal );
    connect( fileOpenPubKeyAct, &QAction::triggered, this, &MainWindow::viewFileOpenPubKey );
    fileMenu->addAction( fileOpenPubKeyAct );

    QAction *fileOpenCMSAct = new QAction( tr( "Open CMS" ), this );
    bVal = isView( ACT_FILE_OPEN_CMS );
    fileOpenCMSAct->setCheckable( true );
    fileOpenCMSAct->setChecked( bVal );
    connect( fileOpenCMSAct, &QAction::triggered, this, &MainWindow::viewFileOpenCMS );
    fileMenu->addAction( fileOpenCMSAct );

    QAction *fileSaveAct = new QAction( tr( "Save" ), this );
    bVal = isView( ACT_FILE_SAVE );
    fileSaveAct->setCheckable( true );
    fileSaveAct->setChecked( bVal );
    connect( fileSaveAct, &QAction::triggered, this, &MainWindow::viewFileSave );
    fileMenu->addAction( fileSaveAct );

    QAction *filePrintAct = new QAction( tr( "Print" ), this );
    bVal = isView( ACT_FILE_PRINT );
    filePrintAct->setCheckable( true );
    filePrintAct->setChecked( bVal );
    connect( filePrintAct, &QAction::triggered, this, &MainWindow::viewFilePrint );
    fileMenu->addAction( filePrintAct );



    QAction *editExpandAllAct = new QAction( tr( "Expand All"), this );
    bVal = isView( ACT_EDIT_EXPAND_ALL );
    editExpandAllAct->setCheckable(true);
    editExpandAllAct->setChecked(bVal);
    connect( editExpandAllAct, &QAction::triggered, this, &MainWindow::viewEditExpandAll );
    editMenu->addAction( editExpandAllAct );

    QAction *editExpandNodeAct = new QAction( tr( "Expand Node"), this );
    bVal = isView( ACT_EDIT_EXPAND_NODE );
    editExpandNodeAct->setCheckable(true);
    editExpandNodeAct->setChecked(bVal);
    connect( editExpandNodeAct, &QAction::triggered, this, &MainWindow::viewEditExpandNode );
    editMenu->addAction( editExpandNodeAct );

    QAction *editCollapseAllAct = new QAction( tr( "Collapse All"), this );
    bVal = isView( ACT_EDIT_COLLAPSE_ALL );
    editCollapseAllAct->setCheckable(true);
    editCollapseAllAct->setChecked(bVal);
    connect( editCollapseAllAct, &QAction::triggered, this, &MainWindow::viewEditCollapseAll );
    editMenu->addAction( editCollapseAllAct );

    QAction *editCollapseNodeAct = new QAction( tr( "Collapse Node"), this );
    bVal = isView( ACT_EDIT_COLLAPSE_NODE );
    editCollapseNodeAct->setCheckable(true);
    editCollapseNodeAct->setChecked(bVal);
    connect( editCollapseNodeAct, &QAction::triggered, this, &MainWindow::viewEditCollapseNode );
    editMenu->addAction( editCollapseNodeAct );

    QAction *editPrevAct = new QAction( tr( "Previous Node"), this );
    bVal = isView( ACT_EDIT_PREV_NODE );
    editPrevAct->setCheckable(true);
    editPrevAct->setChecked(bVal);
    connect( editPrevAct, &QAction::triggered, this, &MainWindow::viewEditPrev );
    editMenu->addAction( editPrevAct );

    QAction *editNextAct = new QAction( tr( "Next Node"), this );
    bVal = isView( ACT_EDIT_NEXT_NODE );
    editNextAct->setCheckable(true);
    editNextAct->setChecked(bVal);
    connect( editNextAct, &QAction::triggered, this, &MainWindow::viewEditNext );
    editMenu->addAction( editNextAct );

    QAction *editFindNodeAct = new QAction( tr( "Find"), this );
    bVal = isView( ACT_EDIT_FIND_NODE );
    editFindNodeAct->setCheckable(true);
    editFindNodeAct->setChecked(bVal);
    connect( editFindNodeAct, &QAction::triggered, this, &MainWindow::viewEditFindNode );
    editMenu->addAction( editFindNodeAct );

    QAction *toolDecodeDataAct = new QAction( tr( "Decode BER"), this );
    bVal = isView( ACT_TOOL_DECODE_DATA );
    toolDecodeDataAct->setCheckable(true);
    toolDecodeDataAct->setChecked(bVal);
    connect( toolDecodeDataAct, &QAction::triggered, this, &MainWindow::viewToolDecodeData );
    toolMenu->addAction( toolDecodeDataAct );

    QAction *toolDataEncodeAct = new QAction( tr( "Data Converter"), this );
    bVal = isView( ACT_TOOL_DATA_CONVERTER );
    toolDataEncodeAct->setCheckable(true);
    toolDataEncodeAct->setChecked(bVal);
    connect( toolDataEncodeAct, &QAction::triggered, this, &MainWindow::viewToolDataConverter );
    toolMenu->addAction( toolDataEncodeAct );

    QAction *toolNumTransAct = new QAction( tr( "Num Converter"), this );
    bVal = isView( ACT_TOOL_NUM_CONVERTER );
    toolNumTransAct->setCheckable(true);
    toolNumTransAct->setChecked(bVal);
    connect( toolNumTransAct, &QAction::triggered, this, &MainWindow::viewToolNumConverter );
    toolMenu->addAction( toolNumTransAct );

    QAction *toolOIDInfoAct = new QAction( tr( "OID Information"), this );
    bVal = isView( ACT_TOOL_OID_INFO );
    toolOIDInfoAct->setCheckable(true);
    toolOIDInfoAct->setChecked(bVal);
    connect( toolOIDInfoAct, &QAction::triggered, this, &MainWindow::viewToolOIDInfo );
    toolMenu->addAction( toolOIDInfoAct );

    QAction *toolMakeBERAct = new QAction( tr( "Make BER"), this );
    bVal = isView( ACT_TOOL_MAKE_BER );
    toolMakeBERAct->setCheckable(true);
    toolMakeBERAct->setChecked(bVal);
    connect( toolMakeBERAct, &QAction::triggered, this, &MainWindow::viewToolMakeBER );
    toolMenu->addAction( toolMakeBERAct );

    QAction *toolBERCheckAct = new QAction( tr( "BER Check"), this );
    bVal = isView( ACT_TOOL_BER_CHECK );
    toolBERCheckAct->setCheckable(true);
    toolBERCheckAct->setChecked(bVal);
    connect( toolBERCheckAct, &QAction::triggered, this, &MainWindow::viewToolBERCheck );
    toolMenu->addAction( toolBERCheckAct );

    QAction *toolGetURIAct = new QAction( tr( "Get BER from URI"), this );
    bVal = isView( ACT_TOOL_GET_URI );
    toolGetURIAct->setCheckable(true);
    toolGetURIAct->setChecked(bVal);
    connect( toolGetURIAct, &QAction::triggered, this, &MainWindow::viewToolGetURI );
    toolMenu->addAction( toolGetURIAct );


    QAction *cryptKeyManAct = new QAction( tr( "KeyManage"), this );
    bVal = isView( ACT_CRYPT_KEY_MAN );
    cryptKeyManAct->setCheckable(true);
    cryptKeyManAct->setChecked(bVal);
    connect( cryptKeyManAct, &QAction::triggered, this, &MainWindow::viewCryptKeyMan );
    cryptMenu->addAction( cryptKeyManAct );

    QAction *cryptHashAct = new QAction( tr( "Hash"), this );
    bVal = isView( ACT_CRYPT_HASH );
    cryptHashAct->setCheckable(true);
    cryptHashAct->setChecked(bVal);
    connect( cryptHashAct, &QAction::triggered, this, &MainWindow::viewCryptHash );
    cryptMenu->addAction( cryptHashAct );

    QAction *cryptMACAct = new QAction( tr( "Message Authentication Code"), this );
    bVal = isView( ACT_CRYPT_MAC );
    cryptMACAct->setCheckable(true);
    cryptMACAct->setChecked(bVal);
    connect( cryptMACAct, &QAction::triggered, this, &MainWindow::viewCryptMAC );
    cryptMenu->addAction( cryptMACAct );

    QAction *cryptEncDecAct = new QAction( tr( "Encrypt/Decrypt"), this );
    bVal = isView( ACT_CRYPT_ENC_DEC );
    cryptEncDecAct->setCheckable(true);
    cryptEncDecAct->setChecked(bVal);
    connect( cryptEncDecAct, &QAction::triggered, this, &MainWindow::viewCryptEncDec );
    cryptMenu->addAction( cryptEncDecAct );

    QAction *cryptSignVerifyAct = new QAction( tr( "Sign/Verify"), this );
    bVal = isView( ACT_CRYPT_SIGN_VERIFY );
    cryptSignVerifyAct->setCheckable(true);
    cryptSignVerifyAct->setChecked(bVal);
    connect( cryptSignVerifyAct, &QAction::triggered, this, &MainWindow::viewCryptSignVerify );
    cryptMenu->addAction( cryptSignVerifyAct );

    QAction *cryptPubEncAct = new QAction( tr( "PubKey Encrypt/Decrypt"), this );
    bVal = isView( ACT_CRYPT_PUB_ENC );
    cryptPubEncAct->setCheckable(true);
    cryptPubEncAct->setChecked(bVal);
    connect( cryptPubEncAct, &QAction::triggered, this, &MainWindow::viewCryptPubEnc );
    cryptMenu->addAction( cryptPubEncAct );

    QAction *cryptKeyAgreeAct = new QAction( tr( "Key Agreement"), this );
    bVal = isView( ACT_CRYPT_KEY_AGREE );
    cryptKeyAgreeAct->setCheckable(true);
    cryptKeyAgreeAct->setChecked(bVal);
    connect( cryptKeyAgreeAct, &QAction::triggered, this, &MainWindow::viewCryptKeyAgree );
    cryptMenu->addAction( cryptKeyAgreeAct );

    QAction *cryptPKCS7Act = new QAction( tr( "PKCS7"), this );
    bVal = isView( ACT_CRYPT_PKCS7 );
    cryptPKCS7Act->setCheckable(true);
    cryptPKCS7Act->setChecked(bVal);
    connect( cryptPKCS7Act, &QAction::triggered, this, &MainWindow::viewCryptPKCS7 );
    cryptMenu->addAction( cryptPKCS7Act );

    QAction *cryptSSSAct = new QAction( tr( "Shamir Secret Sharing"), this );
    bVal = isView( ACT_CRYPT_SSS );
    cryptSSSAct->setCheckable(true);
    cryptSSSAct->setChecked(bVal);
    connect( cryptSSSAct, &QAction::triggered, this, &MainWindow::viewCryptSSS );
    cryptMenu->addAction( cryptSSSAct );

    QAction *cryptCertPVDAct = new QAction( tr( "Certificate Path Validation"), this );
    bVal = isView( ACT_CRYPT_CERT_PVD );
    cryptCertPVDAct->setCheckable(true);
    cryptCertPVDAct->setChecked(bVal);
    connect( cryptCertPVDAct, &QAction::triggered, this, &MainWindow::viewCryptCertPVD );
    cryptMenu->addAction( cryptCertPVDAct );

    QAction *cryptOTPGenAct = new QAction( tr( "OTP Generator"), this );
    bVal = isView( ACT_CRYPT_OTP_GEN );
    cryptOTPGenAct->setCheckable(true);
    cryptOTPGenAct->setChecked(bVal);
    connect( cryptOTPGenAct, &QAction::triggered, this, &MainWindow::viewCryptOTPGen );
    cryptMenu->addAction( cryptOTPGenAct );

    QAction *cryptVIDAct = new QAction( tr( "VID"), this );
    bVal = isView( ACT_CRYPT_VID );
    cryptVIDAct->setCheckable(true);
    cryptVIDAct->setChecked(bVal);
    connect( cryptVIDAct, &QAction::triggered, this, &MainWindow::viewCryptVID );
    cryptMenu->addAction( cryptVIDAct );

    QAction *cryptBNCalcAct = new QAction( tr( "BN Calculator"), this );
    bVal = isView( ACT_CRYPT_BN_CALC );
    cryptBNCalcAct->setCheckable(true);
    cryptBNCalcAct->setChecked(bVal);
    connect( cryptBNCalcAct, &QAction::triggered, this, &MainWindow::viewCryptBNCalc );
    cryptMenu->addAction( cryptBNCalcAct );

    QAction *serviceKeyPairManAct = new QAction( tr( "KeyPair Manage"), this );
    bVal = isView( ACT_SERVICE_KEY_PAIR_MAN );
    serviceKeyPairManAct->setCheckable(true);
    serviceKeyPairManAct->setChecked(bVal);
    connect( serviceKeyPairManAct, &QAction::triggered, this, &MainWindow::viewServiceKeyPairMan );
    serviceMenu->addAction( serviceKeyPairManAct );

    QAction *serviceCertManAct = new QAction( tr( "Certificate Manage"), this );
    bVal = isView( ACT_SERVICE_CERT_MAN );
    serviceCertManAct->setCheckable(true);
    serviceCertManAct->setChecked(bVal);
    connect( serviceCertManAct, &QAction::triggered, this, &MainWindow::viewServiceCertMan );
    serviceMenu->addAction( serviceCertManAct );

    QAction *serviceKeyListAct = new QAction( tr( "Key List"), this );
    bVal = isView( ACT_SERVICE_KEY_LIST );
    serviceKeyListAct->setCheckable(true);
    serviceKeyListAct->setChecked(bVal);
    connect( serviceKeyListAct, &QAction::triggered, this, &MainWindow::viewServiceKeyList );
    serviceMenu->addAction( serviceKeyListAct );

    QAction *serviceSSLVerifyAct = new QAction( tr( "SSL Check"), this );
    bVal = isView( ACT_SERVICE_SSL_CHECK );
    serviceSSLVerifyAct->setCheckable(true);
    serviceSSLVerifyAct->setChecked(bVal);
    connect( serviceSSLVerifyAct, &QAction::triggered, this, &MainWindow::viewServiceSSLCheck );
    serviceMenu->addAction( serviceSSLVerifyAct );

    QAction *serviceX509CompAct = new QAction( tr( "X509 Compare"), this );
    bVal = isView( ACT_SERVICE_X509_COMP );
    serviceX509CompAct->setCheckable(true);
    serviceX509CompAct->setChecked(bVal);
    connect( serviceX509CompAct, &QAction::triggered, this, &MainWindow::viewServiceX509Comp );
    serviceMenu->addAction( serviceX509CompAct );

    QAction *serviceDocSignerAct = new QAction( tr( "Document Signer"), this );
    bVal = isView( ACT_SERVICE_DOC_SIGNER );
    serviceDocSignerAct->setCheckable(true);
    serviceDocSignerAct->setChecked(bVal);
    connect( serviceDocSignerAct, &QAction::triggered, this, &MainWindow::viewServiceDocSigner );
    serviceMenu->addAction( serviceDocSignerAct );

    QAction *serviceCAVPAct = new QAction( tr( "CAVP"), this );
    bVal = isView( ACT_SERVICE_CAVP );
    serviceCAVPAct->setCheckable(true);
    serviceCAVPAct->setChecked(bVal);
    connect( serviceCAVPAct, &QAction::triggered, this, &MainWindow::viewServiceCAVP );
    serviceMenu->addAction( serviceCAVPAct );

    QAction *protoOCSPAct = new QAction( tr( "OCSP client"), this );
    bVal = isView( ACT_PROTO_OCSP );
    protoOCSPAct->setCheckable(true);
    protoOCSPAct->setChecked(bVal);
    connect( protoOCSPAct, &QAction::triggered, this, &MainWindow::viewProtoOCSP );
    protoMenu->addAction( protoOCSPAct );

    QAction *protoTSPAct = new QAction( tr( "TSP client"), this );
    bVal = isView( ACT_PROTO_TSP );
    protoTSPAct->setCheckable(true);
    protoTSPAct->setChecked(bVal);
    connect( protoTSPAct, &QAction::triggered, this, &MainWindow::viewProtoTSP );
    protoMenu->addAction( protoTSPAct );

    QAction *protoCMPAct = new QAction( tr( "CMP client"), this );
    bVal = isView( ACT_PROTO_CMP );
    protoCMPAct->setCheckable(true);
    protoCMPAct->setChecked(bVal);
    connect( protoCMPAct, &QAction::triggered, this, &MainWindow::viewProtoCMP );
    protoMenu->addAction( protoCMPAct );

    QAction *protoSCEPAct = new QAction( tr( "SCEP client"), this );
    bVal = isView( ACT_PROTO_SCEP );
    protoSCEPAct->setCheckable(true);
    protoSCEPAct->setChecked(bVal);
    connect( protoSCEPAct, &QAction::triggered, this, &MainWindow::viewProtoSCEP );
    protoMenu->addAction( protoSCEPAct );

    QAction *protoACMEAct = new QAction( tr( "ACME client"), this );
    bVal = isView( ACT_PROTO_ACME );
    protoACMEAct->setCheckable(true);
    protoACMEAct->setChecked(bVal);
    connect( protoACMEAct, &QAction::triggered, this, &MainWindow::viewProtoACME );
    protoMenu->addAction( protoACMEAct );

    QAction *kmipDecodeTTLVAct = new QAction( tr( "Decode TTLV"), this );
    bVal = isView( ACT_KMIP_DECODE_TTLV );
    kmipDecodeTTLVAct->setCheckable(true);
    kmipDecodeTTLVAct->setChecked(bVal);
    connect( kmipDecodeTTLVAct, &QAction::triggered, this, &MainWindow::viewKMIPDecodeTTLV );
    kmipMenu->addAction( kmipDecodeTTLVAct );

    QAction *kmipMakeTTLVAct = new QAction( tr( "Make TTLV"), this );
    bVal = isView( ACT_KMIP_MAKE_TTLV );
    kmipMakeTTLVAct->setCheckable(true);
    kmipMakeTTLVAct->setChecked(bVal);
    connect( kmipMakeTTLVAct, &QAction::triggered, this, &MainWindow::viewKMIPMakeTTLV );
    kmipMenu->addAction( kmipMakeTTLVAct );

    QAction *kmipEncodeTTLVAct = new QAction( tr( "TTLV Encoder"), this );
    bVal = isView( ACT_KMIP_ENCODE_TTLV );
    kmipEncodeTTLVAct->setCheckable(true);
    kmipEncodeTTLVAct->setChecked(bVal);
    connect( kmipEncodeTTLVAct, &QAction::triggered, this, &MainWindow::viewKMIPEncodeTTLV );
    kmipMenu->addAction( kmipEncodeTTLVAct );

    QAction *kmipClientTTLVAct = new QAction( tr( "TTLV Client"), this );
    bVal = isView( ACT_KMIP_CLIENT_TTLV );
    kmipClientTTLVAct->setCheckable(true);
    kmipClientTTLVAct->setChecked(bVal);
    connect( kmipClientTTLVAct, &QAction::triggered, this, &MainWindow::viewKMIPClientTTLV );
    kmipMenu->addAction( kmipClientTTLVAct );

    QAction *helpSettingsAct = new QAction( tr( "Settings"), this );
    bVal = isView( ACT_HELP_SETTINGS );
    helpSettingsAct->setCheckable(true);
    helpSettingsAct->setChecked(bVal);
    connect( helpSettingsAct, &QAction::triggered, this, &MainWindow::viewHelpSettings );
    helpMenu->addAction( helpSettingsAct );

    QAction *helpClearLogAct = new QAction( tr( "Clear Log"), this );
    bVal = isView( ACT_HELP_CLEAR_LOG );
    helpClearLogAct->setCheckable(true);
    helpClearLogAct->setChecked(bVal);
    connect( helpClearLogAct, &QAction::triggered, this, &MainWindow::viewHelpClearLog );
    helpMenu->addAction( helpClearLogAct );

    QAction *helpHaltLogAct = new QAction( tr( "Halt Log"), this );
    bVal = isView( ACT_HELP_HALT_LOG );
    helpHaltLogAct->setCheckable(true);
    helpHaltLogAct->setChecked(bVal);
    connect( helpHaltLogAct, &QAction::triggered, this, &MainWindow::viewHelpHaltLog );
    helpMenu->addAction( helpHaltLogAct );

    QAction *helpContentAct = new QAction( tr( "Content"), this );
    bVal = isView( ACT_HELP_CONTENT );
    helpContentAct->setCheckable(true);
    helpContentAct->setChecked(bVal);
    connect( helpContentAct, &QAction::triggered, this, &MainWindow::viewHelpContent );
    helpMenu->addAction( helpContentAct );

    QAction *helpAboutAct = new QAction( tr( "About"), this );
    bVal = isView( ACT_HELP_ABOUT );
    helpAboutAct->setCheckable(true);
    helpAboutAct->setChecked(bVal);
    connect( helpAboutAct, &QAction::triggered, this, &MainWindow::viewHelpAbout );
    helpMenu->addAction( helpAboutAct );

    QAction *setDefaultAct = new QAction( tr( "Set Default" ), this );
    connect( setDefaultAct, &QAction::triggered, this, &MainWindow::viewSetDefault );
    viewMenu->addAction( setDefaultAct );
}

void MainWindow::createFileActions()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    file_tool_ = addToolBar(tr("File"));

    file_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT) );
    file_tool_->layout()->setSpacing(0);

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    new_act_ = new QAction( newIcon, tr("&New"), this );
    new_act_->setShortcut(QKeySequence::New);
    new_act_->setStatusTip(tr("Open new window"));
    connect( new_act_, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction(new_act_);
    if( isView( ACT_FILE_NEW ) ) file_tool_->addAction(new_act_);

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    open_act_ = new QAction( openIcon, tr("&Open..."), this );
    open_act_->setShortcut(QKeySequence::Open);
    open_act_->setStatusTip(tr("Open BER file"));
    connect( open_act_, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(open_act_);
    if( isView( ACT_FILE_OPEN ) ) file_tool_->addAction(open_act_);

    const QIcon openCertIcon = QIcon::fromTheme("document-cert", QIcon(":/images/cert.png"));
    open_cert_act_ = new QAction( openCertIcon, tr("Open &Certificate"), this );
    open_cert_act_->setShortcut(QKeySequence(Qt::Key_F2));
    open_cert_act_->setStatusTip(tr("Open certificate file"));
    connect( open_cert_act_, &QAction::triggered, this, &MainWindow::openCert);
    fileMenu->addAction(open_cert_act_);
    if( isView( ACT_FILE_OPEN_CERT ) ) file_tool_->addAction( open_cert_act_ );

    const QIcon openCRLIcon = QIcon::fromTheme("document-crl", QIcon(":/images/crl.png"));
    open_crl_act_ = new QAction( openCRLIcon, tr("Open CR&L"), this );
    open_crl_act_->setShortcut(QKeySequence(Qt::Key_F3));
    open_crl_act_->setStatusTip(tr("Open CRL file"));
    connect( open_crl_act_, &QAction::triggered, this, &MainWindow::openCRL);
    fileMenu->addAction(open_crl_act_);
    if( isView( ACT_FILE_OPEN_CRL) ) file_tool_->addAction( open_crl_act_ );

    const QIcon openCSRIcon = QIcon::fromTheme("document-csr", QIcon(":/images/csr.png"));
    open_csr_act_ = new QAction( openCSRIcon, tr("Open CS&R"), this );
    open_csr_act_->setShortcut(QKeySequence(Qt::Key_F4));
    open_csr_act_->setStatusTip(tr("Open CSR file"));
    connect( open_csr_act_, &QAction::triggered, this, &MainWindow::openCSR);
    fileMenu->addAction(open_csr_act_);
    if( isView( ACT_FILE_OPEN_CSR ) ) file_tool_->addAction( open_csr_act_ );

    const QIcon priKeyIcon = QIcon::fromTheme("document-csr", QIcon(":/images/pri_key.png"));

    open_pri_key_act_ = new QAction( priKeyIcon, tr("Open &PrivateKey"), this );
    open_pri_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_R));
    open_pri_key_act_->setStatusTip(tr("Open private key file"));
    connect( open_pri_key_act_, &QAction::triggered, this, &MainWindow::openPriKey);
    fileMenu->addAction(open_pri_key_act_);
    if( isView( ACT_FILE_OPEN_PRI_KEY ) ) file_tool_->addAction( open_pri_key_act_ );

    const QIcon pubKeyIcon = QIcon::fromTheme("document-csr", QIcon(":/images/pub_key.png"));
    open_pub_key_act_ = new QAction( pubKeyIcon, tr("&Open PublicKey"), this );
    open_pub_key_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_U));
    open_pub_key_act_->setStatusTip(tr("Open public key file"));
    connect( open_pub_key_act_, &QAction::triggered, this, &MainWindow::openPubKey);
    fileMenu->addAction(open_pub_key_act_);
    if( isView( ACT_FILE_OPEN_PUB_KEY ) ) file_tool_->addAction( open_pub_key_act_ );


    const QIcon openCMSIcon = QIcon::fromTheme("CMS", QIcon(":/images/cms_open.png"));

    open_cms_act_ = new QAction( openCMSIcon, tr("Open C&MS"), this );
    open_cms_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_M));
    open_cms_act_->setStatusTip(tr("Open CMS file"));
    connect( open_cms_act_, &QAction::triggered, this, &MainWindow::openCMS);
    fileMenu->addAction(open_cms_act_);
    if( isView( ACT_FILE_OPEN_CMS ) ) file_tool_->addAction( open_cms_act_ );

    const QIcon saveIcon = QIcon::fromTheme("document-save", QIcon(":/images/save.png"));
    save_act_ = new QAction(saveIcon, tr("&Save"), this);
    save_act_->setShortcuts(QKeySequence::Save);
    save_act_->setStatusTip(tr("Save BER file"));
    connect(save_act_, &QAction::triggered, this, &MainWindow::save);
    fileMenu->addAction(save_act_);
    if( isView( ACT_FILE_SAVE ) ) file_tool_->addAction(save_act_);

    const QIcon saveAsIcon = QIcon::fromTheme("document-save-as", QIcon(":/images/save.png"));
    save_as_act_ = fileMenu->addAction(saveAsIcon, tr("Save &As..."), this, &MainWindow::saveAs);
    save_as_act_->setShortcuts(QKeySequence::SaveAs);
    save_as_act_->setStatusTip(tr("Save BER file with another name"));
    if( isView( ACT_FILE_SAVE_AS ) ) file_tool_->addAction( save_as_act_ );

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
    print_act_ = new QAction(printIcon, tr("&Print"), this);
    print_act_->setShortcut(QKeySequence::Print);
    connect( print_act_, &QAction::triggered, this, &MainWindow::print);
    fileMenu->addAction(print_act_);
    if( isView( ACT_FILE_PRINT ) ) file_tool_->addAction( print_act_ );

    print_pre_act_ = new QAction(printIcon, tr("&Print Preview"), this);
    print_pre_act_->setStatusTip(tr( "Print preview"));
    connect( print_pre_act_, &QAction::triggered, this, &MainWindow::filePrintPreview);
    fileMenu->addAction(print_pre_act_);
    if( isView( ACT_FILE_PRINT_PREVEIW ) ) file_tool_->addAction( print_pre_act_ );


    fileMenu->addSeparator();

    quit_act_ = new QAction( tr("&Quit"), this );
    quit_act_->setStatusTip( tr( "Quit BerEditor" ));
    quit_act_->setShortcut(QKeySequence::Quit);
    connect( quit_act_, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction(quit_act_);

    if( berApplet->isLicense() == false )
    {
        open_pri_key_act_->setEnabled(false);
        open_pub_key_act_->setEnabled(false);
        open_cms_act_->setEnabled( false );
    }
}

void MainWindow::createEditActions()
{
    QMenu *editMenu = menuBar()->addMenu(tr("&Edit"));
    edit_tool_ = addToolBar(tr("Edit"));
    edit_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    edit_tool_->layout()->setSpacing(0);

    const QIcon copyIcon = QIcon::fromTheme("edit-copy", QIcon(":/images/copy.png"));
    copy_act_ = new QAction(copyIcon, tr("&Copy Information"), this);
    copy_act_->setShortcuts(QKeySequence::Copy);
    copy_act_->setStatusTip(tr("Copy the current selection's contents to the clipboard"));
    connect( copy_act_, &QAction::triggered, this, &MainWindow::copy );
    editMenu->addAction(copy_act_);
    if( isView( ACT_EDIT_COPY_INFO )) edit_tool_->addAction(copy_act_);

    copy_as_hex_act_ = new QAction(copyIcon, tr("Copy As &Hex"), this);
    copy_as_hex_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_X));
    copy_as_hex_act_->setStatusTip(tr("Copy as hex value"));
    connect( copy_as_hex_act_, &QAction::triggered, this, &MainWindow::copyAsHex );
    editMenu->addAction( copy_as_hex_act_ );
    if( isView( ACT_EDIT_COPY_AS_HEX )) edit_tool_->addAction(copy_as_hex_act_);

    copy_as_base64_act_ = new QAction(copyIcon, tr("Copy As &Base64"), this);
    copy_as_base64_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_B));
    copy_as_base64_act_->setStatusTip(tr("Copy as Base64 value"));
    connect( copy_as_base64_act_, &QAction::triggered, this, &MainWindow::copyAsBase64 );
    editMenu->addAction( copy_as_base64_act_ );
    if( isView( ACT_EDIT_COPY_AS_BASE64 )) edit_tool_->addAction( copy_as_base64_act_ );

    const QIcon expandAllIcon = QIcon::fromTheme("expand-all", QIcon(":/images/expand_all.png"));
    expand_all_act_ = new QAction(expandAllIcon, tr("&Expand All"), this );
    expand_all_act_->setShortcut( QKeySequence(Qt::Key_F5) );
    expand_all_act_->setStatusTip(tr("Expand all nodes"));
    connect( expand_all_act_, &QAction::triggered, this, &MainWindow::treeExpandAll );
    editMenu->addAction(expand_all_act_);
    if( isView( ACT_EDIT_EXPAND_ALL )) edit_tool_->addAction( expand_all_act_ );

    const QIcon expandNodeIcon = QIcon::fromTheme("expand-node", QIcon(":/images/expand_node.png"));
    expand_node_act_ = new QAction(expandNodeIcon, tr("&Expand Node"), this );
    expand_node_act_->setStatusTip(tr("Node expansion"));
    expand_node_act_->setShortcut( QKeySequence(Qt::Key_F6));
    connect( expand_node_act_, &QAction::triggered, this, &MainWindow::treeExpandNode );
    editMenu->addAction(expand_node_act_);
    if( isView( ACT_EDIT_EXPAND_NODE )) edit_tool_->addAction( expand_node_act_);

    const QIcon collapseAllIcon = QIcon::fromTheme("collapse-all", QIcon(":/images/collapse_all.png"));
    collapse_all_act_ = new QAction(collapseAllIcon, tr("&Collapse All"), this );
    collapse_all_act_->setStatusTip(tr("Collapse all nodes"));
    collapse_all_act_->setShortcut( QKeySequence(Qt::Key_F7));
    connect( collapse_all_act_, &QAction::triggered, this, &MainWindow::treeCollapseAll );
    editMenu->addAction(collapse_all_act_);
    if( isView( ACT_EDIT_COLLAPSE_ALL )) edit_tool_->addAction(collapse_all_act_ );

    const QIcon collapseNodeIcon = QIcon::fromTheme("collapse-node", QIcon(":/images/collapse_node.png"));
    collapse_node_act_ = new QAction(collapseNodeIcon, tr("&Collapse Node"), this );
    collapse_node_act_->setStatusTip(tr("Node collapse"));
    collapse_node_act_->setShortcut( QKeySequence(Qt::Key_F8));
    connect( collapse_node_act_, &QAction::triggered, this, &MainWindow::treeCollapseNode );
    editMenu->addAction(collapse_node_act_);
    if( isView( ACT_EDIT_COLLAPSE_NODE )) edit_tool_->addAction(collapse_node_act_ );

    const QIcon prevIcon = QIcon::fromTheme("Prev", QIcon(":/images/prev.png"));
    prev_act_ = new QAction( prevIcon, tr("&Previous Node"), this );
    prev_act_->setStatusTip(tr("Previous Node"));
    prev_act_->setShortcut( QKeySequence(Qt::CTRL | Qt::Key_Left));
    connect( prev_act_, &QAction::triggered, this, &MainWindow::prevNode );
    editMenu->addAction( prev_act_);
    if( isView( ACT_EDIT_PREV_NODE )) edit_tool_->addAction( prev_act_ );

    const QIcon nextIcon = QIcon::fromTheme("Next", QIcon(":/images/next.png"));
    next_act_ = new QAction( nextIcon, tr("&Next Node"), this );
    next_act_->setStatusTip(tr("Previous Node"));
    next_act_->setShortcut( QKeySequence(Qt::CTRL | Qt::Key_Right));
    connect( next_act_, &QAction::triggered, this, &MainWindow::nextNode );
    editMenu->addAction( next_act_);
    if( isView( ACT_EDIT_NEXT_NODE )) edit_tool_->addAction( next_act_ );

    const QIcon findIcon = QIcon::fromTheme("find", QIcon(":/images/find.png"));
    find_node_act_ = new QAction( findIcon, tr("&Find"), this );
    find_node_act_->setStatusTip(tr("Finding BER values"));
    find_node_act_->setShortcut( QKeySequence(Qt::CTRL | Qt::Key_F));
    connect( find_node_act_, &QAction::triggered, this, &MainWindow::findNode );
    editMenu->addAction( find_node_act_);
    if( isView( ACT_EDIT_FIND_NODE )) edit_tool_->addAction( find_node_act_ );

    if( berApplet->isLicense() == false )
    {
        find_node_act_->setEnabled( false );
    }
}

void MainWindow::createToolActions()
{
    QMenu *toolMenu = menuBar()->addMenu(tr("&Tool"));
    tool_tool_ = addToolBar(tr("Tool"));
    tool_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    tool_tool_->layout()->setSpacing(0);

    const QIcon decodeIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/decode.png"));
    decode_data_act_ = new QAction(decodeIcon, tr("&Decode BER"), this);
    decode_data_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_D));
    connect( decode_data_act_, &QAction::triggered, this, &MainWindow::runDecodeData );
    decode_data_act_->setStatusTip(tr("BER data decoding"));
    toolMenu->addAction( decode_data_act_ );
    if( isView( ACT_TOOL_DECODE_DATA ) ) tool_tool_->addAction( decode_data_act_ );

    const QIcon dataTransIcon = QIcon::fromTheme("data-trans", QIcon(":/images/data_trans.png"));
    data_encode_act_ = new QAction( dataTransIcon, tr("Data &Converter"), this );
    data_encode_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_E));
    connect( data_encode_act_, &QAction::triggered, this, &MainWindow::dataConvert );
    data_encode_act_->setStatusTip(tr("Converting data characters" ));
    toolMenu->addAction( data_encode_act_ );
    if( isView( ACT_TOOL_DATA_CONVERTER ) ) tool_tool_->addAction( data_encode_act_ );

    const QIcon numTransIcon = QIcon::fromTheme("number-converter", QIcon(":/images/two.png"));
    num_converter_act_ = new QAction( numTransIcon, tr("&Num Converter"), this);
    num_converter_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_N));
    connect( num_converter_act_, &QAction::triggered, this, &MainWindow::numConverter );
    num_converter_act_->setStatusTip(tr("Converting number" ));
    toolMenu->addAction( num_converter_act_ );
    if( isView( ACT_TOOL_NUM_CONVERTER ) ) tool_tool_->addAction( num_converter_act_ );

    const QIcon oidIcon = QIcon::fromTheme("tool-oid", QIcon(":/images/oid.png"));
    oid_act_ = new QAction(oidIcon, tr("&OID Information"), this);
    oid_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_I));
    connect( oid_act_, &QAction::triggered, this, &MainWindow::oidInfo );
    oid_act_->setStatusTip(tr("View Object Identifier information"));
    toolMenu->addAction( oid_act_ );
    if( isView( ACT_TOOL_OID_INFO ) ) tool_tool_->addAction( oid_act_ );

    const QIcon berIcon = QIcon::fromTheme("ber-insert", QIcon(":/images/ber.png"));
    make_ber_act_ = new QAction(berIcon, tr("Make &BER"), this);
    make_ber_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_B));
    connect( make_ber_act_, &QAction::triggered, this, &MainWindow::runMakeBER );
    make_ber_act_->setStatusTip(tr("Creating BER data"));
    toolMenu->addAction( make_ber_act_ );
    if( isView( ACT_TOOL_MAKE_BER ) ) tool_tool_->addAction( make_ber_act_ );

    const QIcon typeIcon = QIcon::fromTheme("ber-insert", QIcon(":/images/type_check.png"));
    ber_check_act_ = new QAction(typeIcon, tr("&Check BER"), this);
    ber_check_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_C));
    connect( ber_check_act_, &QAction::triggered, this, &MainWindow::runBERCheck );
    ber_check_act_->setStatusTip(tr("Check BER data"));
    toolMenu->addAction( ber_check_act_ );
    if( isView( ACT_TOOL_BER_CHECK ) ) tool_tool_->addAction( ber_check_act_ );

    const QIcon uriIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/uri.png"));
    get_uri_act_ = new QAction(uriIcon, tr("&Get BER from URI"), this);
    get_uri_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_U));
    connect( get_uri_act_, &QAction::triggered, this, &MainWindow::getURI );
    get_uri_act_->setStatusTip(tr("Reading BER data from a URI"));
    toolMenu->addAction( get_uri_act_ );
    if( isView( ACT_TOOL_GET_URI ) ) tool_tool_->addAction( get_uri_act_ );

    menuBar()->addSeparator();

    if( berApplet->isLicense() == false )
    {
        make_ber_act_->setEnabled( false );
        ber_check_act_->setEnabled( false );
    }
}

void MainWindow::createCryptographyActions()
{
    QMenu *cryptMenu = menuBar()->addMenu(tr("&Cryptography"));
    crypt_tool_ = addToolBar( "Cryptography" );
    crypt_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    crypt_tool_->layout()->setSpacing(0);

    const QIcon keyIcon = QIcon::fromTheme("key-man", QIcon(":/images/key.png"));
    key_man_act_ = new QAction( keyIcon, tr("&Key Manage"), this );
    key_man_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_K));
    connect( key_man_act_, &QAction::triggered, this, &MainWindow::keyManage );
    key_man_act_->setStatusTip(tr("Deriving keys and encrypting/decrypting keys" ));
    cryptMenu->addAction( key_man_act_ );
    if( isView( ACT_CRYPT_KEY_MAN ) ) crypt_tool_->addAction( key_man_act_ );

    const QIcon hashIcon = QIcon::fromTheme("Hash", QIcon(":/images/hash.png"));
    hash_act_ = new QAction( hashIcon, tr("&Hash"), this );
    hash_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_D));
    connect( hash_act_, &QAction::triggered, this, &MainWindow::hash );
    hash_act_->setStatusTip(tr("Creating a hash value" ));
    cryptMenu->addAction( hash_act_ );
    if( isView( ACT_CRYPT_HASH ) ) crypt_tool_->addAction( hash_act_ );

    const QIcon macIcon = QIcon::fromTheme("MAC", QIcon(":/images/mac.png"));
    mac_act_ = new QAction( macIcon, tr("M&essage Authentication Code"), this );
    mac_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M));
    connect( mac_act_, &QAction::triggered, this, &MainWindow::mac );
    mac_act_->setStatusTip(tr("Create Message Authentication Code value" ));
    cryptMenu->addAction( mac_act_ );
    if( isView( ACT_CRYPT_MAC ) ) crypt_tool_->addAction( mac_act_ );

    const QIcon encIcon = QIcon::fromTheme("Encrypt_Decrypt", QIcon(":/images/enc.png"));
    enc_dec_act_ = new QAction( encIcon, tr("&Encrypt/Decrypt"), this );
    enc_dec_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_E));
    connect( enc_dec_act_, &QAction::triggered, this, &MainWindow::encDec );
    enc_dec_act_->setStatusTip(tr("Encrypt/decrypt data" ));
    cryptMenu->addAction( enc_dec_act_ );
    if( isView( ACT_CRYPT_ENC_DEC ) ) crypt_tool_->addAction( enc_dec_act_ );

    const QIcon signIcon = QIcon::fromTheme("Sign/Verify", QIcon(":/images/sign.png"));
    sign_verify_act_ = new QAction( signIcon, tr("&Sign/Verify"), this );
    sign_verify_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_S));
    connect( sign_verify_act_, &QAction::triggered, this, &MainWindow::signVerify );
    sign_verify_act_->setStatusTip(tr("Signing/Verifying Data" ));
    cryptMenu->addAction( sign_verify_act_ );
    if( isView( ACT_CRYPT_SIGN_VERIFY ) ) crypt_tool_->addAction( sign_verify_act_ );

    const QIcon pubEncIcon = QIcon::fromTheme("PubKey Encrypt/Decrypt", QIcon(":/images/pub_enc.png"));
    pub_enc_dec_act_ = new QAction( pubEncIcon, tr("&PubKey Encrypt/Decrypt"), this );
    pub_enc_dec_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_P));
    connect( pub_enc_dec_act_, &QAction::triggered, this, &MainWindow::pubEncDec );
    pub_enc_dec_act_->setStatusTip(tr("Encrypt/decrypt data with public key" ));
    cryptMenu->addAction( pub_enc_dec_act_ );
    if( isView( ACT_CRYPT_PUB_ENC ) ) crypt_tool_->addAction( pub_enc_dec_act_ );

    const QIcon agreeIcon = QIcon::fromTheme("Key Agreement", QIcon(":/images/agree.png"));
    key_agree_act_ = new QAction( agreeIcon, tr("Key &Agreement"), this );
    key_agree_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_A));
    connect( key_agree_act_, &QAction::triggered, this, &MainWindow::keyAgree );
    key_agree_act_->setStatusTip(tr("DH or ECDH key agreement" ));
    cryptMenu->addAction( key_agree_act_ );
    if( isView( ACT_CRYPT_KEY_AGREE ) ) crypt_tool_->addAction( key_agree_act_ );


    const QIcon p7Icon = QIcon::fromTheme("PKCS7", QIcon(":/images/p7.png"));
    pkcs7_act_ = new QAction( p7Icon, tr("&PKCS7"), this );
    pkcs7_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_G));
    connect( pkcs7_act_, &QAction::triggered, this, &MainWindow::pkcs7 );
    pkcs7_act_->setStatusTip(tr("Creating and validating PKCS7 messages" ));
    cryptMenu->addAction( pkcs7_act_ );
    if( isView( ACT_CRYPT_PKCS7 ) ) crypt_tool_->addAction( pkcs7_act_ );

    const QIcon sssIcon = QIcon::fromTheme("SSS", QIcon(":/images/sss.png"));
    sss_act_ = new QAction( sssIcon, tr("&Shamir Secret Sharing"), this );
    sss_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_R));
    connect( sss_act_, &QAction::triggered, this, &MainWindow::sss );
    sss_act_->setStatusTip(tr("Splitting and merging keys using Shamir Secret Sharing" ));
    cryptMenu->addAction( sss_act_ );
    if( isView( ACT_CRYPT_SSS ) ) crypt_tool_->addAction( sss_act_ );

    const QIcon certPVDIcon = QIcon::fromTheme("Cert PathValidation", QIcon(":/images/cert_pvd.png"));
    cert_pvd_act_ = new QAction( certPVDIcon, tr( "Certificate &Path Validation"), this );
    cert_pvd_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_T));
    connect( cert_pvd_act_, &QAction::triggered, this, &MainWindow::certPVD );
    cert_pvd_act_->setStatusTip(tr("Verifying the certificate path"));
    cryptMenu->addAction( cert_pvd_act_ );
    if( isView( ACT_CRYPT_CERT_PVD ) ) crypt_tool_->addAction( cert_pvd_act_ );

    const QIcon otpIcon = QIcon::fromTheme("OTP", QIcon(":/images/otp.png"));
    gen_otp_act_ = new QAction( otpIcon, tr("&OTP Generator"), this );
    gen_otp_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_O));
    connect( gen_otp_act_, &QAction::triggered, this, &MainWindow::genOTP );
    gen_otp_act_->setStatusTip(tr("Generate OTP value" ));
    cryptMenu->addAction( gen_otp_act_ );
    if( isView( ACT_CRYPT_OTP_GEN ) ) crypt_tool_->addAction( gen_otp_act_ );

    const QIcon vidIcon = QIcon::fromTheme("VID", QIcon(":/images/vid.png"));
    vid_act_ = new QAction( vidIcon, tr("&VID"), this );
    vid_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_I));
    connect( vid_act_, &QAction::triggered, this, &MainWindow::VID );
    vid_act_->setStatusTip(tr("Generating and validating VID values" ));
    cryptMenu->addAction( vid_act_ );
    if( isView( ACT_CRYPT_VID ) ) crypt_tool_->addAction( vid_act_ );

    const QIcon calcIcon = QIcon::fromTheme("BN Calc", QIcon(":/images/bn_calc.png"));
    calc_act_ = new QAction( calcIcon, tr("&BN Calculator"), this );
    calc_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_B));
    connect( calc_act_, &QAction::triggered, this, &MainWindow::BNCalc );
    calc_act_->setStatusTip(tr("Bignum calculator" ));
    cryptMenu->addAction( calc_act_ );
    if( isView( ACT_CRYPT_BN_CALC ) ) crypt_tool_->addAction( calc_act_ );

    if( berApplet->isLicense() == false )
    {
        key_man_act_->setEnabled( false );
        hash_act_->setEnabled( false );
        mac_act_->setEnabled( false );
        enc_dec_act_->setEnabled( false );
        sign_verify_act_->setEnabled( false );
        pub_enc_dec_act_->setEnabled( false );
        key_agree_act_->setEnabled( false );
        pkcs7_act_->setEnabled( false );
        sss_act_->setEnabled( false );
        cert_pvd_act_->setEnabled( false );
        gen_otp_act_->setEnabled( false );
        vid_act_->setEnabled( false );
        calc_act_->setEnabled( false );
    }
}

void MainWindow::createServiceActions()
{
    QMenu *serviceMenu = menuBar()->addMenu( tr("&Service" ));
    service_tool_ = addToolBar( tr( "Service" ));
    service_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    service_tool_->layout()->setSpacing(0);

    const QIcon keyPairIcon = QIcon::fromTheme("KeyPair Manage", QIcon(":/images/keypair.png"));
    key_pair_man_act_ = new QAction( keyPairIcon, tr( "Key&Pair Manage" ), this );
    key_pair_man_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_Y ));
    connect( key_pair_man_act_, &QAction::triggered, this, &MainWindow::keyPairMan );
    key_pair_man_act_->setStatusTip( tr( "List and manage asymmetric keys" ));
    serviceMenu->addAction( key_pair_man_act_ );
    if( isView( ACT_SERVICE_KEY_PAIR_MAN ) ) service_tool_->addAction( key_pair_man_act_ );

    const QIcon certManIcon = QIcon::fromTheme("Certificate Manage", QIcon(":/images/cert_man.png"));
    cert_man_act_ = new QAction( certManIcon, tr( "&Certificate Manage" ), this );
    cert_man_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M ));
    connect( cert_man_act_, &QAction::triggered, this, &MainWindow::certMan );
    cert_man_act_->setStatusTip( tr( "List and manage certificates and keys" ));
    serviceMenu->addAction( cert_man_act_ );
    if( isView( ACT_SERVICE_CERT_MAN ) ) service_tool_->addAction( cert_man_act_ );

    const QIcon keyListIcon = QIcon::fromTheme("Key List", QIcon(":/images/keylist.png"));
    key_list_act_ = new QAction( keyListIcon, tr( "&Key List" ), this );
    key_list_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_L ));
    connect( key_list_act_, &QAction::triggered, this, &MainWindow::keyList );
    key_list_act_->setStatusTip( tr( "List and manage symmetric keys" ));
    serviceMenu->addAction( key_list_act_ );
    if( isView( ACT_SERVICE_KEY_LIST ) ) service_tool_->addAction( key_list_act_ );

    const QIcon sslIcon = QIcon::fromTheme( "service-ssl", QIcon(":/images/ssl.png"));
    ssl_act_ = new QAction(sslIcon, tr("&SSL Check"), this);
    ssl_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_V));
    connect( ssl_act_, &QAction::triggered, this, &MainWindow::sslCheck );
    ssl_act_->setStatusTip(tr("Check SSL and TLS protocols"));
    serviceMenu->addAction( ssl_act_ );
    if( isView( ACT_SERVICE_SSL_CHECK ) ) service_tool_->addAction( ssl_act_ );

    const QIcon x509Icon = QIcon::fromTheme( "service-x509", QIcon(":/images/compare.png"));
    x509_comp_act_ = new QAction(x509Icon, tr("&X509 Compare"), this);
    x509_comp_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_C));
    connect( x509_comp_act_, &QAction::triggered, this, &MainWindow::x509Compare );
    x509_comp_act_->setStatusTip(tr("Compare X509"));
    serviceMenu->addAction( x509_comp_act_ );
    if( isView( ACT_SERVICE_X509_COMP ) ) service_tool_->addAction( x509_comp_act_ );

    const QIcon signerIcon = QIcon::fromTheme( "document-signer", QIcon(":/images/doc_signer.png"));
    doc_signer_act_ = new QAction(signerIcon, tr("&Docment Signer"), this);
    doc_signer_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_D));
    connect( doc_signer_act_, &QAction::triggered, this, &MainWindow::docSigner );
    doc_signer_act_->setStatusTip(tr("Document Signer"));
    serviceMenu->addAction( doc_signer_act_ );
    if( isView( ACT_SERVICE_DOC_SIGNER ) ) service_tool_->addAction( doc_signer_act_ );

    const QIcon cavpIcon = QIcon::fromTheme( "tool-cavp", QIcon(":/images/cavp.png"));
    cavp_act_ = new QAction(cavpIcon, tr("&CAVP"), this);
    cavp_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_F));
    connect( cavp_act_, &QAction::triggered, this, &MainWindow::CAVP );
    cavp_act_->setStatusTip(tr("Cryptography Algorithm Valication Program"));
    serviceMenu->addAction( cavp_act_ );
    if( isView( ACT_SERVICE_CAVP ) ) service_tool_->addAction( cavp_act_ );

    if( berApplet->isLicense() == false )
    {
        key_pair_man_act_->setEnabled( false );
        cert_man_act_->setEnabled( false );
        key_list_act_->setEnabled( false );
        cavp_act_->setEnabled( false );
        ssl_act_->setEnabled( false );
        x509_comp_act_->setEnabled( false );
        doc_signer_act_->setEnabled( false );
    }

}

void MainWindow::createProtocolActions()
{
    QMenu *protoMenu = menuBar()->addMenu( tr("&Protocol" ));
    proto_tool_ = addToolBar( tr( "Protocol" ));
    proto_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    proto_tool_->layout()->setSpacing(0);

    const QIcon ocspIcon = QIcon::fromTheme( "ocsp_client", QIcon(":/images/ocsp.png"));
    ocsp_act_ = new QAction( ocspIcon, tr( "&OCSP client"), this );
    ocsp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_O));
    ocsp_act_->setStatusTip( tr( "OCSP Client Tool" ));
    connect( ocsp_act_, &QAction::triggered, this, &MainWindow::ocspClient );
    protoMenu->addAction( ocsp_act_ );
    if( isView( ACT_PROTO_OCSP ) ) proto_tool_->addAction( ocsp_act_ );

    const QIcon tspIcon = QIcon::fromTheme( "tsp_client", QIcon(":/images/tsp.png"));
    tsp_act_ = new QAction( tspIcon, tr( "&TSP client"), this );
    tsp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T));
    tsp_act_->setStatusTip( tr( "TSP Client Tool" ));
    connect( tsp_act_, &QAction::triggered, this, &MainWindow::tspClient );
    protoMenu->addAction( tsp_act_ );
    if( isView( ACT_PROTO_TSP ) ) proto_tool_->addAction( tsp_act_ );

    const QIcon cmpIcon = QIcon::fromTheme( "cmp_client", QIcon(":/images/cmp.png"));
    cmp_act_ = new QAction( cmpIcon, tr( "&CMP client"), this );
    cmp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_C));
    cmp_act_->setStatusTip( tr( "CMP Client Tool" ));
    connect( cmp_act_, &QAction::triggered, this, &MainWindow::cmpClient );
    protoMenu->addAction( cmp_act_ );
    if( isView( ACT_PROTO_CMP ) ) proto_tool_->addAction( cmp_act_ );

    const QIcon scepIcon = QIcon::fromTheme( "scep_client", QIcon(":/images/scep.png"));
    scep_act_ = new QAction( scepIcon, tr( "&SCEP client"), this );
    scep_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_S));
    scep_act_->setStatusTip( tr( "SCEP Client Tool" ));
    connect( scep_act_, &QAction::triggered, this, &MainWindow::scepClient );
    protoMenu->addAction( scep_act_ );
    if( isView( ACT_PROTO_SCEP ) ) proto_tool_->addAction( scep_act_ );

    const QIcon acmeIcon = QIcon::fromTheme( "acme_client", QIcon(":/images/acme.png"));
    acme_act_ = new QAction( acmeIcon, tr( "&ACME client"), this );
    acme_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_A));
    acme_act_->setStatusTip( tr( "ACME Client Tool" ));
    connect( acme_act_, &QAction::triggered, this, &MainWindow::acmeClient );
    protoMenu->addAction( acme_act_ );
    if( isView( ACT_PROTO_ACME ) ) proto_tool_->addAction( acme_act_ );

    if( berApplet->isLicense() == false )
    {
        ocsp_act_->setEnabled( false );
        tsp_act_->setEnabled( false );
        cmp_act_->setEnabled( false );
        scep_act_->setEnabled( false );
        acme_act_->setEnabled( false );
    }
}

void MainWindow::createKMIPActions()
{
    QMenu *kmipMenu = menuBar()->addMenu( tr("&KMIP" ));
    kmip_tool_ = addToolBar( tr( "KMIP" ));
    kmip_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    kmip_tool_->layout()->setSpacing(0);

    const QIcon decodeKMIPIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/decode_ttlv.png"));
    ttlv_decode_act_ = new QAction(decodeKMIPIcon, tr("&Decode TTLV"), this);
    ttlv_decode_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_K));
    connect( ttlv_decode_act_, &QAction::triggered, this, &MainWindow::runDecodeTTLV );
    ttlv_decode_act_->setStatusTip(tr("Decoding KMIP TTLV Messages"));
    kmipMenu->addAction( ttlv_decode_act_ );
    if( isView( ACT_KMIP_DECODE_TTLV ) ) kmip_tool_->addAction( ttlv_decode_act_ );

    const QIcon makeTTLVIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/kms.png"));
    ttlv_make_act_ = new QAction(makeTTLVIcon, tr("&Make TTLV"), this);
    ttlv_make_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_Y));
    connect( ttlv_make_act_, &QAction::triggered, this, &MainWindow::runMakeTTLV );
    ttlv_make_act_->setStatusTip(tr("Creating a KMIP TTLV Message"));
    kmipMenu->addAction( ttlv_make_act_ );
    if( isView( ACT_KMIP_MAKE_TTLV ) ) kmip_tool_->addAction( ttlv_make_act_ );

    const QIcon ttlvEncoderIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/kms_encoder.png"));
    ttlv_encode_act_ = new QAction(ttlvEncoderIcon, tr("&TTLV Encoder"), this);
    ttlv_encode_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_M));
    connect( ttlv_encode_act_, &QAction::triggered, this, &MainWindow::ttlvEncoder );
    ttlv_encode_act_->setStatusTip(tr("KMIP TTLV Client Messages"));
    kmipMenu->addAction( ttlv_encode_act_ );
    if( isView( ACT_KMIP_ENCODE_TTLV ) ) kmip_tool_->addAction( ttlv_encode_act_ );

    const QIcon ttlvClientIcon = QIcon::fromTheme("tool-insert", QIcon(":/images/kms_client.png"));
    ttlv_client_act_ = new QAction(ttlvClientIcon, tr("TTLV &Client"), this);
    ttlv_client_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_P));
    connect( ttlv_client_act_, &QAction::triggered, this, &MainWindow::ttlvClient );
    ttlv_client_act_->setStatusTip(tr("KMIP TTLV Client Tool"));
    kmipMenu->addAction( ttlv_client_act_ );
    if( isView( ACT_KMIP_CLIENT_TTLV ) ) kmip_tool_->addAction( ttlv_client_act_ );

    if( berApplet->isLicense() == false )
    {
        ttlv_decode_act_->setEnabled( false );
        ttlv_make_act_->setEnabled( false );
        ttlv_encode_act_->setEnabled( false );
        ttlv_client_act_->setEnabled( false );
    }
}

void MainWindow::createHelpActions()
{
    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    help_tool_ = addToolBar(tr("Help"));
    help_tool_->setIconSize( QSize(TOOL_BAR_WIDTH,TOOL_BAR_HEIGHT));
    help_tool_->layout()->setSpacing(0);

    const QIcon settingIcon = QIcon::fromTheme("berview-help", QIcon(":/images/setting.png"));
    setting_act_ = new QAction( settingIcon, tr("&Settings"), this );
    connect( setting_act_, &QAction::triggered, this, &MainWindow::setting );
    setting_act_->setStatusTip(tr("Set up your environment"));
    helpMenu->addAction( setting_act_ );
    if( isView( ACT_HELP_SETTINGS ) ) help_tool_->addAction( setting_act_ );

    const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
    clear_log_act_ = new QAction( clearIcon, tr("&Clear Log"), this );
    connect( clear_log_act_, &QAction::triggered, this, &MainWindow::clearLog );
    clear_log_act_->setShortcut( QKeySequence(Qt::Key_F9));
    clear_log_act_->setStatusTip(tr("Clear log tab messages"));
    helpMenu->addAction( clear_log_act_ );
    if( isView( ACT_HELP_CLEAR_LOG ) ) help_tool_->addAction( clear_log_act_ );

    QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_en.png" ));
    halt_log_act_ = new QAction( logIcon, tr( "&Log Halt" ), this );
    connect( halt_log_act_, &QAction::triggered, this, &MainWindow::toggleLog );
    halt_log_act_->setShortcut( QKeySequence(Qt::Key_F10));
    halt_log_act_->setStatusTip( tr( "Halt logging in the log tab" ));
    helpMenu->addAction( halt_log_act_ );
    if( isView( ACT_HELP_HALT_LOG ) ) help_tool_->addAction( halt_log_act_ );

    QIcon infoIcon = QIcon::fromTheme( "content", QIcon(":/images/info.png"));
    content_act_ = new QAction( infoIcon, tr( "Content" ), this );
    connect( content_act_, &QAction::triggered, this, &MainWindow::content );
    content_act_->setShortcut( QKeySequence(Qt::Key_F11 ));
    content_act_->setStatusTip( tr("PKI related information content" ));
    helpMenu->addAction( content_act_ );
    if( isView( ACT_HELP_CONTENT ) ) help_tool_->addAction( content_act_ );

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    lcn_act_ = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcn_act_, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcn_act_ );
    lcn_act_->setStatusTip(tr("License Information and Registration"));
    if( isView( ACT_HELP_LICENSE_INFO ) ) help_tool_->addAction( lcn_act_ );

    const QIcon aboutIcon = QIcon::fromTheme("berview-icon", QIcon(":/images/bereditor.png"));

    bug_issue_act_ = new QAction( aboutIcon, tr("Bug or Issue Report"), this);
    connect( bug_issue_act_, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bug_issue_act_ );
    bug_issue_act_->setStatusTip(tr("Report bugs and issues"));
    if( isView( ACT_HELP_BUG_REPORT ) ) help_tool_->addAction( bug_issue_act_ );

    qna_act_ = new QAction( aboutIcon, tr("Q and A"), this);
    connect( qna_act_, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qna_act_ );
    qna_act_->setStatusTip(tr("Question and Answer"));
    if( isView( ACT_HELP_QNA ) ) help_tool_->addAction( qna_act_ );

    about_act_ = new QAction( aboutIcon, tr("&About BerEditor"), this );
    connect( about_act_, &QAction::triggered, this, &MainWindow::about );
    about_act_->setShortcut( QKeySequence(Qt::Key_F1));
    about_act_->setStatusTip(tr("About BerEditor"));
    helpMenu->addAction( about_act_ );
    if( isView( ACT_HELP_ABOUT ) ) help_tool_->addAction( about_act_ );

    if( berApplet->isLicense() == false )
    {
        clear_log_act_->setEnabled( false );
        halt_log_act_->setEnabled( false );
        content_act_->setEnabled( false );
    }
}

void MainWindow::createActions()
{
    createFileActions();
    createEditActions();

    if( berApplet->isLicense() ) createViewActions();

    createToolActions();
    createCryptographyActions();
    createServiceActions();
    createProtocolActions();
    createKMIPActions();
    createHelpActions();

    menuBar()->show();
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createCryptoDlg()
{
//    key_man_dlg_ = new KeyManDlg;
//    gen_hash_dlg_ = new GenHashDlg;
//    gen_mac_dlg_ = new GenMacDlg;
//    enc_dec_dlg_ = new EncDecDlg;
//    sign_verify_dlg_ = new SignVerifyDlg;
//    pub_enc_dec_dlg_ = new PubEncDecDlg;
//    key_agree_dlg_ = new KeyAgreeDlg;
//    pkcs7_dlg_ = new PKCS7Dlg;
//    sss_dlg_ = new SSSDlg;
//    cert_pvd_dlg_ = new CertPVDDlg;
//    gen_otp_dlg_ = new GenOTPDlg;
//    cavp_dlg_ = new CAVPDlg;
//    ssl_check_dlg_ = new SSLCheckDlg;
//    vid_dlg_ = new VIDDlg;
//    bn_calc_dlg_ = new BNCalcDlg;
//    key_pair_man_dlg_ = new KeyPairManDlg;
//    key_pair_man_dlg_->setMode( KeyPairModeBase );
//    ocsp_client_dlg_ = new OCSPClientDlg;
//    tsp_client_dlg_ = new TSPClientDlg;
//    cmp_client_dlg_ = new CMPClientDlg;
//    scep_client_dlg_ = new SCEPClientDlg;
//    acme_client_dlg_ = new ACMEClientDlg;
//    cert_man_dlg_ = new CertManDlg;
//    cert_man_dlg_->setMode( ManModeBase );
//    ttlv_encoder_dlg_ = new TTLVEncoderDlg;
//    ttlv_encoder_dlg_->setManage();
//    ttlv_client_dlg_ = new TTLVClientDlg;
//    content_ = new ContentMain;
//    find_dlg_ = new FindDlg;
//    key_list_dlg_ = new KeyListDlg;
//    key_list_dlg_->setManage( true );
//    x509_comp_dlg_ = new X509CompareDlg;
//    doc_signer_dlg_ = new DocSignerDlg;
}

void MainWindow::newFile()
{
    QString cmd = berApplet->cmd();
    QProcess *process = new QProcess();
    process->setProgram( berApplet->cmd() );
    process->start();
}

void MainWindow::changeTableTab()
{
    if( isTTLV() == true )
    {
        ttlv_model_->getTreeView()->viewCurrent();
    }
    else
    {
        ber_model_->getTreeView()->viewCurrent();
    }
}

void MainWindow::runMakeBER()
{
    int ret = 0;

    MakeBerDlg makeBer;
    makeBer.mFirstSetCheck->hide();
    makeBer.mPrimitiveCombo->setCurrentText(JS_NAME_SEQUENCE);

    ret = makeBer.exec();

    if( ret == QDialog::Accepted )
    {
        BIN binData = {0,0};
        QString strData = makeBer.getData();

        BIN binBer = ber_model_->getBER();
        if( binBer.nLen > 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr("Existing data already exists. Would you like to change it?"), this, true );
            if( bVal == false ) return;
        }

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
        decodeData( &binData );
        JS_BIN_reset( &binData );
    }
}

void MainWindow::runDecodeData()
{
    int ret = -1;

    DecodeDataDlg deData(this);
    ret = deData.exec();
}

void MainWindow::runDecodeTTLV()
{
    DecodeTTLVDlg decodeTTLV;
    decodeTTLV.exec();
}

void MainWindow::runMakeTTLV()
{
    MakeTTLVDlg makeTTLV;
    makeTTLV.setHeadLabel( tr( "Make TTLV [ Tag Type Length Value ]" ) );
    makeTTLV.mFirstSetCheck->hide();
    makeTTLV.mTypeCombo->setCurrentText( "Structure" );

    if( makeTTLV.exec() == QDialog::Accepted )
    {
        BIN binData = {0,0};
        QString strData = makeTTLV.getData();

        BIN binTTLV = ttlv_model_->getTTLV();
        if( binTTLV.nLen > 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr("Existing data already exists. Would you like to change it?"), this, true );
            if( bVal == false ) return;
        }

        JS_BIN_decodeHex( strData.toStdString().c_str(), &binData );
        berApplet->decodeTTLV(&binData);
        JS_BIN_reset( &binData );
    }
}

void MainWindow::runBERCheck()
{
    BERCheckDlg berCheck;
    berCheck.exec();
}

void MainWindow::ttlvClient()
{
    if( ttlv_client_dlg_ == nullptr )
    {
        ttlv_client_dlg_ = new TTLVClientDlg;
    }

    ttlv_client_dlg_->show();
    ttlv_client_dlg_->raise();
    ttlv_client_dlg_->activateWindow();
}

void MainWindow::ttlvEncoder()
{
    if( ttlv_encoder_dlg_ == nullptr )
    {
        ttlv_encoder_dlg_ = new TTLVEncoderDlg;
        ttlv_encoder_dlg_->setManage();
    }

    ttlv_encoder_dlg_->show();
    ttlv_encoder_dlg_->raise();
    ttlv_encoder_dlg_->activateWindow();
}

void MainWindow::numConverter()
{
    NumConverterDlg numConverterDlg;
    numConverterDlg.exec();
}

void MainWindow::open()
{
    QString strPath = berApplet->getBERPath();
    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath, false );

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
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );
    BIN binCert = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCert );

    if( JS_PKI_isCert( &binCert ) == 1 )
    {
        CertInfoDlg certInfo;
        certInfo.setCertPath( fileName );
        certInfo.exec();
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
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CRL, strPath );
    BIN binCRL = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCRL );

    if( JS_PKI_isCRL( &binCRL ) == 1 )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRLPath( fileName );
        crlInfo.exec();
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
                certInfo.setCertPath( fileName );
                certInfo.exec();
            }
        }
        else if( JS_PKI_isCSR( &binCRL) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CSR. Open it as CSR information?"), this, true );
            if( bVal == true )
            {
                CSRInfoDlg csrInfo;
                csrInfo.setReqPath( fileName );
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
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_CSR, strPath );
    BIN binCSR = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCSR );

    if( JS_PKI_isCSR( &binCSR ) == 1 )
    {
        CSRInfoDlg csrInfo;
        csrInfo.setReqPath( fileName );
        csrInfo.exec();
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
                certInfo.setCertPath( fileName );
                certInfo.exec();
            }
        }
        else if( JS_PKI_isCRL( &binCSR) == 1 )
        {
            bVal = berApplet->yesOrCancelBox( tr( "This file is CRL. Open it as CRL information?"), this, true );
            if( bVal == true )
            {
                CRLInfoDlg crlInfo;
                crlInfo.setCRLPath( fileName );
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

void MainWindow::openPriKey()
{
    int nKeyType = -1;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    BIN binKey = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binKey );

    nKeyType = JS_PKI_getPriKeyType( &binKey );
    if( nKeyType < 0 )
    {
        nKeyType = JS_PKI_getPubKeyType( &binKey );
        if( nKeyType > 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr( "This file is Public Key. Open it as Public Key?"), this, true );
            if( bVal == true )
            {
                PriKeyInfoDlg priKeyInfo;
                priKeyInfo.setPublicKeyPath( fileName );
                priKeyInfo.exec();

                if( berApplet->settingsMgr()->supportKeyPairChange() == true )
                {
                    BIN binRead = {0,0};
                    priKeyInfo.readPublicKey( &binRead );

                    if( JS_BIN_cmp( &binRead, &binKey ) != 0 )
                    {
                        bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
                        if( bVal == true )
                        {
                            JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PUBLIC_KEY, strPath.toLocal8Bit().toStdString().c_str() );
                            berApplet->messageLog( tr( "Key change saved." ), this );
                        }
                    }

                    JS_BIN_reset( &binRead );
                }
            }
        }
        else
        {
            berApplet->warningBox( tr( "Invalid Private Key" ), this );
        }
    }
    else
    {
        PriKeyInfoDlg priKeyInfo;
        priKeyInfo.setPrivateKeyPath( fileName );
        priKeyInfo.exec();

        if( berApplet->settingsMgr()->supportKeyPairChange() == true )
        {
            BIN binRead = {0,0};
            priKeyInfo.readPrivateKey( &binRead );

            if( JS_BIN_cmp( &binRead, &binKey ) != 0 )
            {
                bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
                if( bVal == true )
                {
                    JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PRIVATE_KEY, strPath.toLocal8Bit().toStdString().c_str() );
                    berApplet->messageLog( tr( "Key change saved." ), this );
                }
            }

            JS_BIN_reset( &binRead );
        }
    }

    JS_BIN_reset( &binKey );
}

void MainWindow::openPubKey()
{
    int nKeyType = -1;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    BIN binKey = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binKey );

    nKeyType = JS_PKI_getPubKeyType( &binKey );
    if( nKeyType < 0 )
    {
        nKeyType = JS_PKI_getPriKeyType( &binKey );
        if( nKeyType > 0 )
        {
            bool bVal = berApplet->yesOrCancelBox( tr( "This file is Private Key. Open it as Private Key?"), this, true );
            if( bVal == true )
            {
                PriKeyInfoDlg priKeyInfo;
                priKeyInfo.setPrivateKeyPath( fileName );
                priKeyInfo.exec();

                if( berApplet->settingsMgr()->getSupportKeyPairChange() == true )
                {
                    BIN binRead = {0,0};
                    priKeyInfo.readPrivateKey( &binRead );

                    if( JS_BIN_cmp( &binRead, &binKey ) != 0 )
                    {
                        bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
                        if( bVal == true )
                        {
                            JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PRIVATE_KEY, strPath.toLocal8Bit().toStdString().c_str() );
                            berApplet->messageLog( tr( "Key change saved." ), this );
                        }
                    }

                    JS_BIN_reset( &binRead );
                }
            }
        }
        else
        {
            berApplet->warningBox( tr( "Invalid Public Key" ), this );
        }
    }
    else
    {
        PriKeyInfoDlg priKeyInfo;
        priKeyInfo.setPublicKeyPath( fileName );
        priKeyInfo.exec();

        if( berApplet->settingsMgr()->supportKeyPairChange() == true )
        {
            BIN binRead = {0,0};
            priKeyInfo.readPublicKey( &binRead );

            if( JS_BIN_cmp( &binRead, &binKey ) != 0 )
            {
                bool bVal = berApplet->yesOrCancelBox( tr( "Do you want to change the original key to the changed key?" ), this, false );
                if( bVal == true )
                {
                    JS_BIN_writePEM( &binRead, JS_PEM_TYPE_PUBLIC_KEY, strPath.toLocal8Bit().toStdString().c_str() );
                    berApplet->messageLog( tr( "Key change saved." ), this );
                }
            }

            JS_BIN_reset( &binRead );
        }
    }

    JS_BIN_reset( &binKey );
}

void MainWindow::openCMS()
{
    int ret = 0;
    int nCMSType = -1;
    QString strPath;

    QString fileName = berApplet->findFile( this, JS_FILE_TYPE_PKCS7, strPath );
    BIN binCMS = {0,0};

    if( fileName.length() < 1 ) return;

    JS_BIN_fileReadBER( fileName.toLocal8Bit().toStdString().c_str(), &binCMS );

    nCMSType = JS_CMS_getType( &binCMS );
    if( nCMSType < 0 )
    {
        berApplet->warningBox( tr( "This message is not CMS.").arg( nCMSType ), this );
        JS_BIN_reset( &binCMS );
        return;
    }

    CMSInfoDlg cmsInfo;
    cmsInfo.setCMS( fileName );
    cmsInfo.exec();

    JS_BIN_reset( &binCMS );
}

void MainWindow::copy()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        ttlv_model_->copy();
    }
    else
    {
        ber_model_->copy();
    }
}

void MainWindow::copyAsHex()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        ttlv_model_->CopyAsHex();
    }
    else
    {
        ber_model_->CopyAsHex();
    }
}

void MainWindow::copyAsBase64()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView())
    {
        ttlv_model_->CopyAsBase64();
    }
    else
    {
        ber_model_->CopyAsBase64();
    }
}

void MainWindow::treeExpandAll()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        ttlv_model_->getTreeView()->treeExpandAll();
    }
    else
    {
        ber_model_->getTreeView()->treeExpandAll();
    }
}

void MainWindow::treeExpandNode()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        ttlv_model_->getTreeView()->treeExpandNode();
    }
    else
    {
        ber_model_->getTreeView()->treeExpandNode();
    }
}

void MainWindow::treeCollapseAll()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        ttlv_model_->getTreeView()->treeCollapseAll();
    }
    else
    {
        ber_model_->getTreeView()->treeCollapseAll();
    }
}

void MainWindow::treeCollapseNode()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView())
    {
        ttlv_model_->getTreeView()->treeCollapseNode();
    }
    else
    {
        ber_model_->getTreeView()->treeCollapseNode();
    }
}

void MainWindow::findNode()
{
    if( find_dlg_ == nullptr )
        find_dlg_ = new FindDlg;

    find_dlg_->show();
    find_dlg_->raise();
    find_dlg_->activateWindow();
}

void MainWindow::prevNode()
{
    if( isTTLV() )
    {
        TTLVTreeItem* pItem = ttlv_model_->currentItem();
        TTLVTreeItem* pNewItem = ttlv_model_->getTreeView()->getPrev( pItem );
        if( pNewItem ) ttlv_model_->setCurrentItem( pNewItem );
    }
    else
    {
        BerItem* pItem = ber_model_->getTreeView()->currentItem();
        BerItem* pNewItem = ber_model_->getTreeView()->getPrev( pItem );
        if( pNewItem ) ber_model_->setCurrentItem( pNewItem );
    }
}

void MainWindow::nextNode()
{
    if( isTTLV() )
    {
        TTLVTreeItem* pItem = ttlv_model_->currentItem();
        TTLVTreeItem* pNewItem = ttlv_model_->getTreeView()->getNext( pItem );
        if( pNewItem ) ttlv_model_->setCurrentItem( pNewItem );
    }
    else
    {
        BerItem* pItem = ber_model_->getTreeView()->currentItem();
        BerItem* pNewItem = ber_model_->getTreeView()->getNext( pItem );
        if( pNewItem ) ber_model_->setCurrentItem( pNewItem );
    }
}

int MainWindow::openBer( const BIN *pBer )
{
    int ret = 0;

    if( JS_KMS_isTTLV( pBer ) == 1 )
    {
        if( berApplet->isLicense() == true )
        {
            bool bVal = berApplet->yesOrNoBox( tr("The BER is TTLV format. Do you open as TTLV format?" ), this );
            if( bVal == true )
            {
                ret = decodeTTLV( pBer );
                return ret;
            }
        }
        else
        {
            berApplet->warningBox( tr( "TTLV decoding requires a license."), this );
            return -1;
        }
    }

    if( JS_PKI_isBER( pBer ) == 0 )
    {
        berApplet->warningBox( tr( "The data is not BER format"), this );
        return -2;
    }

    ber_model_->setBER( pBer );
#ifdef QT_DEBUG
    qint64 us = 0;
    QElapsedTimer timer;
    timer.start();
#endif

    ber_model_->makeTree( berApplet->settingsMgr()->autoExpand() );

#ifdef QT_DEBUG
    us = timer.nsecsElapsed() / 1000;
    berApplet->log( QString("ElapsedTime: %1").arg(getMS(us)));
#endif

    if( hsplitter_->widget(0) != ber_model_->getTreeView() )
        hsplitter_->replaceWidget(0, ber_model_->getTreeView() );

    return 0;
}

bool MainWindow::isChanged()
{
    if( file_path_.length() < 1 || file_path_ == "" )
        return false;

    const BIN& binBer = ber_model_->getBER();

    if( binBer.nLen > 0 )
    {
        BIN binFile = {0,0};

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

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    QTextCursor cursor = log_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );
    cursor.insertText( strMsg );

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
    info_text_->update();
}

void MainWindow::infoClear()
{
    info_text_->clear();
}

QString MainWindow::getInfo()
{
    return info_text_->toPlainText();
}

int MainWindow::berFileOpen(const QString berPath)
{
    BIN binRead = {0,0};

    int ret = JS_BIN_fileReadBER( berPath.toLocal8Bit().toStdString().c_str(), &binRead );

    if( berApplet->isLicense() == true )
    {
        if( ret == JSR_BAD_FILE_FORMAT )
            ret = JS_BIN_fileReadTTLV( berPath.toLocal8Bit().toStdString().c_str(), &binRead );
    }

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
    log_text_->setPlainText( msg );
}

int MainWindow::tableCurrentIndex()
{
    return table_tab_->currentIndex();
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
        QString strippedName = QString( "%1 ").arg(i + 1);
        strippedName += QFileInfo(recentFilePaths.at(i)).fileName();

        recent_file_list_.at(i)->setText(strippedName);
        recent_file_list_.at(i)->setData( recentFilePaths.at(i));
        recent_file_list_.at(i)->setVisible(true);
    }

    for( auto i = itEnd; i < kMaxRecentFiles; ++i )
        recent_file_list_.at(i)->setVisible(false);
}

bool MainWindow::isView( int nAct )
{
    int nValue = -1;
    int nType = nAct & 0xFF000000;

    if( berApplet->isLicense() )
        nValue = berApplet->settingsMgr()->viewValue( nType );
    else
    {
        switch (nType) {
        case VIEW_FILE:
            nValue = kFileDefault;
            break;
        case VIEW_EDIT:
            nValue = kEditDefault;
            break;
        case VIEW_TOOL:
            nValue = kToolDefault;
            break;
        case VIEW_CRYPT:
            nValue = kCryptDefault;
            break;
        case VIEW_SERVICE:
            nValue = kServiceDefault;
            break;
        case VIEW_PROTO:
            nValue = kProtoDefault;
            break;
        case VIEW_KMIP:
            nValue = kKMIPDefault;
            break;
        case VIEW_HELP:
            nValue = kHelpDefault;
            break;
        default:
            break;
        }
    }

    if( nValue < 0 ) return false;

    if( (nValue & nAct) == nAct )
        return true;

    return false;
}

void MainWindow::setView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = berApplet->settingsMgr()->viewValue( nType );
    if( nValue < 0 ) return;

    nValue |= nAct;

    berApplet->settingsMgr()->setViewValue( nValue );
}

void MainWindow::unsetView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = berApplet->settingsMgr()->viewValue( nType );
    if( nValue < 0 ) return;

    if( nValue & nAct ) nValue -= nAct;

    nValue |= nType;

    berApplet->settingsMgr()->setViewValue( nValue );
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

void MainWindow::dataConvert()
{
    DataConverterDlg dataConverterDlg;
    dataConverterDlg.exec();
}

void MainWindow::keyManage()
{
    if( key_man_dlg_ == nullptr )
    {
        key_man_dlg_ = new KeyManDlg;
    }

    key_man_dlg_->show();
    key_man_dlg_->raise();
    key_man_dlg_->activateWindow();
}

void MainWindow::hash()
{
    if( gen_hash_dlg_ == nullptr )
        gen_hash_dlg_ = new GenHashDlg;

    gen_hash_dlg_->show();
    gen_hash_dlg_->raise();
    gen_hash_dlg_->activateWindow();
}

void MainWindow::mac()
{
    if( gen_mac_dlg_ == nullptr )
        gen_mac_dlg_ = new GenMacDlg;

    gen_mac_dlg_->show();
    gen_mac_dlg_->raise();
    gen_mac_dlg_->activateWindow();
}

void MainWindow::mac2( const QString strKey, const QString strIV )
{
    if( gen_mac_dlg_ == nullptr )
        gen_mac_dlg_ = new GenMacDlg;

    gen_mac_dlg_->mKeyTypeCombo->setCurrentText( "Hex" );
    gen_mac_dlg_->mKeyText->setText( strKey );

    gen_mac_dlg_->mIVTypeCombo->setCurrentText( "Hex" );
    gen_mac_dlg_->mIVText->setText( strIV );

    gen_mac_dlg_->show();
    gen_mac_dlg_->raise();
    gen_mac_dlg_->activateWindow();
}

void MainWindow::keyAgree()
{
    if( key_agree_dlg_ == nullptr )
        key_agree_dlg_ = new KeyAgreeDlg;

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
    if( enc_dec_dlg_ == nullptr )
        enc_dec_dlg_ = new EncDecDlg;

    enc_dec_dlg_->show();
    enc_dec_dlg_->raise();
    enc_dec_dlg_->activateWindow();
}

void MainWindow::encDec2( const QString strKey, const QString strIV )
{
    if( enc_dec_dlg_ == nullptr )
        enc_dec_dlg_ = new EncDecDlg;

    enc_dec_dlg_->mKeyTypeCombo->setCurrentText( "Hex" );
    enc_dec_dlg_->mKeyText->setText( strKey );

    enc_dec_dlg_->mIVTypeCombo->setCurrentText( "Hex" );
    enc_dec_dlg_->mIVText->setText( strIV );

    enc_dec_dlg_->show();
    enc_dec_dlg_->raise();
    enc_dec_dlg_->activateWindow();
}

void MainWindow::signVerify()
{
    if( sign_verify_dlg_ == nullptr )
        sign_verify_dlg_ = new SignVerifyDlg;

    sign_verify_dlg_->show();
    sign_verify_dlg_->raise();
    sign_verify_dlg_->activateWindow();
}

void MainWindow::pubEncDec()
{
    if( pub_enc_dec_dlg_ == nullptr )
        pub_enc_dec_dlg_ = new PubEncDecDlg;

    pub_enc_dec_dlg_->show();
    pub_enc_dec_dlg_->raise();
    pub_enc_dec_dlg_->activateWindow();
}

void MainWindow::pkcs7()
{
    if( pkcs7_dlg_ == nullptr )
        pkcs7_dlg_ = new PKCS7Dlg;

    pkcs7_dlg_->show();
    pkcs7_dlg_->raise();
    pkcs7_dlg_->activateWindow();
}

void MainWindow::sss()
{
    if( sss_dlg_ == nullptr )
        sss_dlg_ = new SSSDlg;

    sss_dlg_->show();
    sss_dlg_->raise();
    sss_dlg_->activateWindow();
}

void MainWindow::certPVD()
{
    if( cert_pvd_dlg_ == nullptr )
        cert_pvd_dlg_ = new CertPVDDlg;

    cert_pvd_dlg_->show();
    cert_pvd_dlg_->raise();
    cert_pvd_dlg_->activateWindow();
}

void MainWindow::CAVP()
{
    if( cavp_dlg_ == nullptr )
        cavp_dlg_ = new CAVPDlg;

    cavp_dlg_->show();
    cavp_dlg_->raise();
    cavp_dlg_->activateWindow();
}

void MainWindow::sslCheck()
{
    if( ssl_check_dlg_ == nullptr )
        ssl_check_dlg_ = new SSLCheckDlg;

    ssl_check_dlg_->show();
    ssl_check_dlg_->raise();
    ssl_check_dlg_->activateWindow();
}

void MainWindow::x509Compare()
{
    if( x509_comp_dlg_ == nullptr )
        x509_comp_dlg_ = new X509CompareDlg;

    x509_comp_dlg_->show();
    x509_comp_dlg_->raise();
    x509_comp_dlg_->activateWindow();
}

void MainWindow::docSigner()
{
    if( doc_signer_dlg_ == nullptr )
        doc_signer_dlg_ = new DocSignerDlg;

    doc_signer_dlg_->show();
    doc_signer_dlg_->raise();
    doc_signer_dlg_->activateWindow();
}

void MainWindow::genOTP()
{
    if( gen_otp_dlg_ == nullptr )
        gen_otp_dlg_ = new GenOTPDlg;

    gen_otp_dlg_->show();
    gen_otp_dlg_->raise();
    gen_otp_dlg_->activateWindow();
}

void MainWindow::VID()
{
    if( vid_dlg_ == nullptr )
        vid_dlg_ = new VIDDlg;

    vid_dlg_->show();
    vid_dlg_->raise();
    vid_dlg_->activateWindow();
}

void MainWindow::BNCalc()
{
    if( bn_calc_dlg_ == nullptr )
        bn_calc_dlg_ = new BNCalcDlg;

    bn_calc_dlg_->show();
    bn_calc_dlg_->raise();
    bn_calc_dlg_->activateWindow();
}

void MainWindow::keyPairMan()
{
    if( key_pair_man_dlg_ == nullptr )
    {
        key_pair_man_dlg_ = new KeyPairManDlg;
        key_pair_man_dlg_->setMode( KeyPairModeBase );
    }

    key_pair_man_dlg_->show();
    key_pair_man_dlg_->raise();
    key_pair_man_dlg_->activateWindow();
}

void MainWindow::ocspClient()
{
    if( ocsp_client_dlg_ == nullptr )
        ocsp_client_dlg_ = new OCSPClientDlg;

    ocsp_client_dlg_->show();
    ocsp_client_dlg_->raise();
    ocsp_client_dlg_->activateWindow();
}

void MainWindow::tspClient()
{
    if( tsp_client_dlg_ == nullptr )
        tsp_client_dlg_ = new TSPClientDlg;

    tsp_client_dlg_->show();
    tsp_client_dlg_->raise();
    tsp_client_dlg_->activateWindow();
}

void MainWindow::cmpClient()
{
    if( cmp_client_dlg_ == nullptr )
        cmp_client_dlg_ = new CMPClientDlg;

    cmp_client_dlg_->show();
    cmp_client_dlg_->raise();
    cmp_client_dlg_->activateWindow();
}

void MainWindow::scepClient()
{
    if( scep_client_dlg_ == nullptr )
        scep_client_dlg_ = new SCEPClientDlg;

    scep_client_dlg_->show();
    scep_client_dlg_->raise();
    scep_client_dlg_->activateWindow();
}

void MainWindow::acmeClient()
{
    if( acme_client_dlg_ == nullptr )
        acme_client_dlg_ = new ACMEClientDlg;

    acme_client_dlg_->show();
    acme_client_dlg_->raise();
    acme_client_dlg_->activateWindow();
}

void MainWindow::certMan()
{
    if( cert_man_dlg_ == nullptr )
    {
        cert_man_dlg_ = new CertManDlg;
        cert_man_dlg_->setMode( ManModeBase );
        cert_man_dlg_->setTitle( tr( "Certificate Management" ));
    }

    cert_man_dlg_->show();
    cert_man_dlg_->raise();
    cert_man_dlg_->activateWindow();
}

void MainWindow::keyList()
{
    if( key_list_dlg_ == nullptr )
    {
        key_list_dlg_ = new KeyListDlg;
        key_list_dlg_->setManage( true );
    }

    key_list_dlg_->show();
    key_list_dlg_->raise();
    key_list_dlg_->activateWindow();
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
        QString strMsg = tr("The current data has been changed. Do you want to save the changed data?");
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

bool MainWindow::isTTLV()
{
    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
        return true;
    else
        return false;
}

void MainWindow::runSignVerify( bool bSign, bool bEncPri, const QString strPriPath, const QString strCertPath )
{
    if( sign_verify_dlg_ == nullptr )
        sign_verify_dlg_ = new SignVerifyDlg;

    sign_verify_dlg_->clickClearDataAll();
    sign_verify_dlg_->mCertGroup->setChecked(true);
    sign_verify_dlg_->mEncPrikeyCheck->setChecked( bEncPri );

    sign_verify_dlg_->mPriKeyPath->setText( strPriPath );
    sign_verify_dlg_->mCertPath->setText( strCertPath );

    sign_verify_dlg_->checkEncPriKey();

    if( bSign == true )
    {
        sign_verify_dlg_->mSignRadio->setChecked(true);
        sign_verify_dlg_->checkSign();
    }
    else
    {
        sign_verify_dlg_->mVerifyRadio->setChecked(true);
        sign_verify_dlg_->checkVerify();
    }

    sign_verify_dlg_->show();
    sign_verify_dlg_->raise();
    sign_verify_dlg_->activateWindow();
}

void MainWindow::runPubEncDec( bool bEnc, bool bEncPri, const QString strPriPath, const QString strCertPath )
{
    if( pub_enc_dec_dlg_ == nullptr )
    {
        pub_enc_dec_dlg_ = new PubEncDecDlg;
    }

    pub_enc_dec_dlg_->clickClearDataAll();
    pub_enc_dec_dlg_->mCertGroup->setChecked(true);
    pub_enc_dec_dlg_->mEncPrikeyCheck->setChecked( bEncPri );

    pub_enc_dec_dlg_->mCertPath->setText( strCertPath );
    pub_enc_dec_dlg_->mPriKeyPath->setText( strPriPath );

    pub_enc_dec_dlg_->checkEncPriKey();

    if( bEnc == true )
    {
        pub_enc_dec_dlg_->mEncryptRadio->setChecked(true);

        pub_enc_dec_dlg_->checkEncrypt();
    }
    else
    {
        pub_enc_dec_dlg_->mDecryptRadio->setChecked(true);

        pub_enc_dec_dlg_->checkDecrypt();
    }

    pub_enc_dec_dlg_->show();
    pub_enc_dec_dlg_->raise();
    pub_enc_dec_dlg_->activateWindow();
}


void MainWindow::viewFileNew( bool bChecked )
{
    berApplet->log( QString( "Checked: %1").arg( bChecked ));

    if( bChecked == true )
    {
//        file_tool_->addAction( new_act_ );
        file_tool_->insertAction( open_act_, new_act_ );
        setView( ACT_FILE_NEW );
    }
    else
    {
        file_tool_->removeAction( new_act_ );
        unsetView( ACT_FILE_NEW );
    }
}

void MainWindow::viewFileOpen( bool bChecked )
{
    berApplet->log( QString( "Checked: %1").arg( bChecked ));

    if( bChecked == true )
    {
        file_tool_->insertAction( open_cert_act_, open_act_ );
        setView( ACT_FILE_OPEN );
    }
    else
    {
        file_tool_->removeAction( open_act_ );
        unsetView( ACT_FILE_OPEN );
    }
}

void MainWindow::viewFileOpenCert( bool bChecked )
{
    berApplet->log( QString( "Checked: %1").arg( bChecked ));

    if( bChecked == true )
    {
        file_tool_->insertAction( open_crl_act_, open_cert_act_ );
        setView( ACT_FILE_OPEN_CERT );
    }
    else
    {
        file_tool_->removeAction( open_cert_act_ );
        unsetView( ACT_FILE_OPEN_CERT );
    }
}

void MainWindow::viewFileOpenCRL( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( open_csr_act_, open_crl_act_ );
        setView( ACT_FILE_OPEN_CRL );
    }
    else
    {
        file_tool_->removeAction( open_crl_act_ );
        unsetView( ACT_FILE_OPEN_CRL );
    }
}

void MainWindow::viewFileOpenCSR( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( open_pri_key_act_, open_csr_act_ );
        setView( ACT_FILE_OPEN_CSR );
    }
    else
    {
        file_tool_->removeAction( open_csr_act_ );
        unsetView( ACT_FILE_OPEN_CSR );
    }
}

void MainWindow::viewFileOpenPriKey( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( open_pub_key_act_, open_pri_key_act_ );
        setView( ACT_FILE_OPEN_PRI_KEY );
    }
    else
    {
        file_tool_->removeAction( open_pri_key_act_ );
        unsetView( ACT_FILE_OPEN_PRI_KEY );
    }
}

void MainWindow::viewFileOpenPubKey( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( open_cms_act_, open_pub_key_act_ );
        setView( ACT_FILE_OPEN_PUB_KEY );
    }
    else
    {
        file_tool_->removeAction( open_pub_key_act_ );
        unsetView( ACT_FILE_OPEN_PUB_KEY );
    }
}

void MainWindow::viewFileOpenCMS( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( save_act_, open_cms_act_ );
        setView( ACT_FILE_OPEN_CMS );
    }
    else
    {
        file_tool_->removeAction( open_cms_act_ );
        unsetView( ACT_FILE_OPEN_CMS );
    }
}

void MainWindow::viewFileSave( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( save_as_act_, save_act_ );
        setView( ACT_FILE_SAVE );
    }
    else
    {
        file_tool_->removeAction( save_act_ );
        unsetView( ACT_FILE_SAVE );
    }
}

void MainWindow::viewFilePrint( bool bChecked )
{
    if( bChecked == true )
    {
        file_tool_->insertAction( print_pre_act_, print_act_ );
        setView( ACT_FILE_PRINT );
    }
    else
    {
        file_tool_->removeAction( print_act_ );
        unsetView( ACT_FILE_PRINT );
    }
}

void MainWindow::viewEditExpandAll( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( expand_node_act_, expand_all_act_ );
        setView( ACT_EDIT_EXPAND_ALL );
    }
    else
    {
        edit_tool_->removeAction( expand_all_act_ );
        unsetView( ACT_EDIT_EXPAND_ALL );
    }
}

void MainWindow::viewEditExpandNode( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( collapse_all_act_, expand_node_act_ );
        setView( ACT_EDIT_EXPAND_NODE );
    }
    else
    {
        edit_tool_->removeAction( expand_node_act_ );
        unsetView( ACT_EDIT_EXPAND_NODE );
    }
}

void MainWindow::viewEditCollapseAll( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( collapse_node_act_, collapse_all_act_ );
        setView( ACT_EDIT_COLLAPSE_ALL );
    }
    else
    {
        edit_tool_->removeAction( collapse_all_act_ );
        unsetView( ACT_EDIT_COLLAPSE_ALL );
    }
}

void MainWindow::viewEditCollapseNode( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( prev_act_, collapse_node_act_ );
        setView( ACT_EDIT_COLLAPSE_NODE );
    }
    else
    {
        edit_tool_->removeAction( collapse_node_act_ );
        unsetView( ACT_EDIT_COLLAPSE_NODE );
    }
}

void MainWindow::viewEditPrev( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( next_act_, prev_act_ );
        setView( ACT_EDIT_PREV_NODE );
    }
    else
    {
        edit_tool_->removeAction( prev_act_ );
        unsetView( ACT_EDIT_PREV_NODE );
    }
}

void MainWindow::viewEditNext( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->insertAction( find_node_act_, next_act_ );
        setView( ACT_EDIT_NEXT_NODE );
    }
    else
    {
        edit_tool_->removeAction( next_act_ );
        unsetView( ACT_EDIT_NEXT_NODE );
    }
}

void MainWindow::viewEditFindNode( bool bChecked )
{
    if( bChecked == true )
    {
        edit_tool_->addAction( find_node_act_ );
        setView( ACT_EDIT_FIND_NODE );
    }
    else
    {
        edit_tool_->removeAction( find_node_act_ );
        unsetView( ACT_EDIT_FIND_NODE );
    }
}

void MainWindow::viewToolDecodeData( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( data_encode_act_, decode_data_act_ );
        setView( ACT_TOOL_DECODE_DATA );
    }
    else
    {
        tool_tool_->removeAction( decode_data_act_ );
        unsetView( ACT_TOOL_DECODE_DATA );
    }
}

void MainWindow::viewToolDataConverter( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( num_converter_act_, data_encode_act_ );
        setView( ACT_TOOL_DATA_CONVERTER );
    }
    else
    {
        tool_tool_->removeAction( data_encode_act_ );
        unsetView( ACT_TOOL_DATA_CONVERTER );
    }
}

void MainWindow::viewToolNumConverter( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( oid_act_, num_converter_act_ );
        setView( ACT_TOOL_NUM_CONVERTER );
    }
    else
    {
        tool_tool_->removeAction( num_converter_act_ );
        unsetView( ACT_TOOL_NUM_CONVERTER );
    }
}

void MainWindow::viewToolOIDInfo( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( make_ber_act_, oid_act_ );
        setView( ACT_TOOL_OID_INFO );
    }
    else
    {
        tool_tool_->removeAction( oid_act_ );
        unsetView( ACT_TOOL_OID_INFO );
    }
}

void MainWindow::viewToolMakeBER( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( ber_check_act_, make_ber_act_ );
        setView( ACT_TOOL_MAKE_BER );
    }
    else
    {
        tool_tool_->removeAction( make_ber_act_ );
        unsetView( ACT_TOOL_MAKE_BER );
    }
}

void MainWindow::viewToolBERCheck( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->insertAction( get_uri_act_, ber_check_act_ );
        setView( ACT_TOOL_BER_CHECK );
    }
    else
    {
        tool_tool_->removeAction( ber_check_act_ );
        unsetView( ACT_TOOL_BER_CHECK );
    }
}

void MainWindow::viewToolGetURI( bool bChecked )
{
    if( bChecked == true )
    {
        tool_tool_->addAction( get_uri_act_ );
        setView( ACT_TOOL_GET_URI );
    }
    else
    {
        tool_tool_->removeAction( get_uri_act_ );
        unsetView( ACT_TOOL_GET_URI );
    }
}

void MainWindow::viewCryptKeyMan( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( hash_act_, key_man_act_ );
        setView( ACT_CRYPT_KEY_MAN );
    }
    else
    {
        crypt_tool_->removeAction( key_man_act_ );
        unsetView( ACT_CRYPT_KEY_MAN );
    }
}

void MainWindow::viewCryptHash( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( mac_act_, hash_act_ );
        setView( ACT_CRYPT_HASH );
    }
    else
    {
        crypt_tool_->removeAction( hash_act_ );
        unsetView( ACT_CRYPT_HASH );
    }
}

void MainWindow::viewCryptMAC( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( enc_dec_act_, mac_act_ );
        setView( ACT_CRYPT_MAC );
    }
    else
    {
        crypt_tool_->removeAction( mac_act_ );
        unsetView( ACT_CRYPT_MAC );
    }
}

void MainWindow::viewCryptEncDec( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( sign_verify_act_, enc_dec_act_ );
        setView( ACT_CRYPT_ENC_DEC );
    }
    else
    {
        crypt_tool_->removeAction( enc_dec_act_ );
        unsetView( ACT_CRYPT_ENC_DEC );
    }
}

void MainWindow::viewCryptSignVerify( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( pub_enc_dec_act_, sign_verify_act_ );
        setView( ACT_CRYPT_SIGN_VERIFY );
    }
    else
    {
        crypt_tool_->removeAction( sign_verify_act_ );
        unsetView( ACT_CRYPT_SIGN_VERIFY );
    }
}

void MainWindow::viewCryptPubEnc( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( key_agree_act_, pub_enc_dec_act_ );
        setView( ACT_CRYPT_PUB_ENC );
    }
    else
    {
        crypt_tool_->removeAction( pub_enc_dec_act_ );
        unsetView( ACT_CRYPT_PUB_ENC );
    }
}

void MainWindow::viewCryptKeyAgree( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( pkcs7_act_, key_agree_act_ );
        setView( ACT_CRYPT_KEY_AGREE );
    }
    else
    {
        crypt_tool_->removeAction( key_agree_act_ );
        unsetView( ACT_CRYPT_KEY_AGREE );
    }
}

void MainWindow::viewCryptPKCS7( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( sss_act_, pkcs7_act_ );
        setView( ACT_CRYPT_PKCS7 );
    }
    else
    {
        crypt_tool_->removeAction( pkcs7_act_ );
        unsetView( ACT_CRYPT_PKCS7 );
    }
}

void MainWindow::viewCryptSSS( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( cert_pvd_act_, sss_act_ );
        setView( ACT_CRYPT_SSS );
    }
    else
    {
        crypt_tool_->removeAction( sss_act_ );
        unsetView( ACT_CRYPT_SSS );
    }
}

void MainWindow::viewCryptCertPVD( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( gen_otp_act_, cert_pvd_act_ );
        setView( ACT_CRYPT_CERT_PVD );
    }
    else
    {
        crypt_tool_->removeAction( cert_pvd_act_ );
        unsetView( ACT_CRYPT_CERT_PVD );
    }
}

void MainWindow::viewCryptOTPGen( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( vid_act_, gen_otp_act_ );
        setView( ACT_CRYPT_OTP_GEN );
    }
    else
    {
        crypt_tool_->removeAction( gen_otp_act_ );
        unsetView( ACT_CRYPT_OTP_GEN );
    }
}

void MainWindow::viewCryptVID( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->insertAction( calc_act_, vid_act_ );
        setView( ACT_CRYPT_VID );
    }
    else
    {
        crypt_tool_->removeAction( vid_act_ );
        unsetView( ACT_CRYPT_VID );
    }
}

void MainWindow::viewCryptBNCalc( bool bChecked )
{
    if( bChecked == true )
    {
        crypt_tool_->addAction( calc_act_ );
        setView( ACT_CRYPT_BN_CALC );
    }
    else
    {
        crypt_tool_->removeAction( calc_act_ );
        unsetView( ACT_CRYPT_BN_CALC );
    }
}

void MainWindow::viewServiceKeyPairMan( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( cert_man_act_, key_pair_man_act_ );
        setView( ACT_SERVICE_KEY_PAIR_MAN );
    }
    else
    {
        service_tool_->removeAction( key_pair_man_act_ );
        unsetView( ACT_SERVICE_KEY_PAIR_MAN );
    }
}

void MainWindow::viewServiceCertMan( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( key_list_act_, cert_man_act_ );
        setView( ACT_SERVICE_CERT_MAN );
    }
    else
    {
        service_tool_->removeAction( cert_man_act_ );
        unsetView( ACT_SERVICE_CERT_MAN );
    }
}

void MainWindow::viewServiceKeyList( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( ssl_act_, key_list_act_ );
        setView( ACT_SERVICE_KEY_LIST );
    }
    else
    {
        service_tool_->removeAction( key_list_act_ );
        unsetView( ACT_SERVICE_KEY_LIST );
    }
}

void MainWindow::viewServiceSSLCheck( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( x509_comp_act_, ssl_act_ );
        setView( ACT_SERVICE_SSL_CHECK );
    }
    else
    {
        service_tool_->removeAction( ssl_act_ );
        unsetView( ACT_SERVICE_SSL_CHECK );
    }
}

void MainWindow::viewServiceX509Comp( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( doc_signer_act_, x509_comp_act_ );
        setView( ACT_SERVICE_X509_COMP );
    }
    else
    {
        service_tool_->removeAction( x509_comp_act_ );
        unsetView( ACT_SERVICE_X509_COMP );
    }
}

void MainWindow::viewServiceDocSigner( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->insertAction( cavp_act_, doc_signer_act_ );
        setView( ACT_SERVICE_DOC_SIGNER );
    }
    else
    {
        service_tool_->removeAction( doc_signer_act_ );
        unsetView( ACT_SERVICE_DOC_SIGNER );
    }
}

void MainWindow::viewServiceCAVP( bool bChecked )
{
    if( bChecked == true )
    {
        service_tool_->addAction( cavp_act_ );
        setView( ACT_SERVICE_CAVP );
    }
    else
    {
        service_tool_->removeAction( cavp_act_ );
        unsetView( ACT_SERVICE_CAVP );
    }
}


void MainWindow::viewProtoOCSP( bool bChecked )
{
    if( bChecked == true )
    {
        proto_tool_->insertAction( tsp_act_, ocsp_act_ );
        setView( ACT_PROTO_OCSP );
    }
    else
    {
        proto_tool_->removeAction( ocsp_act_ );
        unsetView( ACT_PROTO_OCSP );
    }
}

void MainWindow::viewProtoTSP( bool bChecked )
{
    if( bChecked == true )
    {
        proto_tool_->insertAction( cmp_act_, tsp_act_ );
        setView( ACT_PROTO_TSP );
    }
    else
    {
        proto_tool_->removeAction( tsp_act_ );
        unsetView( ACT_PROTO_TSP );
    }
}

void MainWindow::viewProtoCMP( bool bChecked )
{
    if( bChecked == true )
    {
        proto_tool_->insertAction( scep_act_, cmp_act_ );
        setView( ACT_PROTO_CMP );
    }
    else
    {
        proto_tool_->removeAction( cmp_act_ );
        unsetView( ACT_PROTO_CMP );
    }
}

void MainWindow::viewProtoSCEP( bool bChecked )
{
    if( bChecked == true )
    {
        proto_tool_->insertAction( acme_act_, scep_act_ );
        setView( ACT_PROTO_SCEP );
    }
    else
    {
        proto_tool_->removeAction( scep_act_ );
        unsetView( ACT_PROTO_SCEP );
    }
}

void MainWindow::viewProtoACME( bool bChecked )
{
    if( bChecked == true )
    {
        proto_tool_->addAction( acme_act_ );
        setView( ACT_PROTO_ACME );
    }
    else
    {
        proto_tool_->removeAction( acme_act_ );
        unsetView( ACT_PROTO_ACME );
    }
}

void MainWindow::viewKMIPDecodeTTLV( bool bChecked )
{
    if( bChecked == true )
    {
        kmip_tool_->insertAction( ttlv_make_act_, ttlv_decode_act_ );
        setView( ACT_KMIP_DECODE_TTLV );
    }
    else
    {
        kmip_tool_->removeAction( ttlv_decode_act_ );
        unsetView( ACT_KMIP_DECODE_TTLV );
    }
}

void MainWindow::viewKMIPMakeTTLV( bool bChecked )
{
    if( bChecked == true )
    {
        kmip_tool_->insertAction( ttlv_encode_act_, ttlv_make_act_ );
        setView( ACT_KMIP_MAKE_TTLV );
    }
    else
    {
        kmip_tool_->removeAction( ttlv_make_act_ );
        unsetView( ACT_KMIP_MAKE_TTLV );
    }
}

void MainWindow::viewKMIPEncodeTTLV( bool bChecked )
{
    if( bChecked == true )
    {
        kmip_tool_->insertAction( ttlv_client_act_, ttlv_encode_act_ );
        setView( ACT_KMIP_ENCODE_TTLV );
    }
    else
    {
        kmip_tool_->removeAction( ttlv_encode_act_ );
        unsetView( ACT_KMIP_ENCODE_TTLV );
    }
}

void MainWindow::viewKMIPClientTTLV( bool bChecked )
{
    if( bChecked == true )
    {
        kmip_tool_->addAction( ttlv_client_act_ );
        setView( ACT_KMIP_CLIENT_TTLV );
    }
    else
    {
        kmip_tool_->removeAction( ttlv_client_act_ );
        unsetView( ACT_KMIP_CLIENT_TTLV );
    }
}

void MainWindow::viewHelpSettings( bool bChecked )
{
    if( bChecked == true )
    {
        help_tool_->insertAction( clear_log_act_, setting_act_ );
        setView( ACT_HELP_SETTINGS );
    }
    else
    {
        help_tool_->removeAction( setting_act_ );
        unsetView( ACT_HELP_SETTINGS );
    }
}

void MainWindow::viewHelpClearLog( bool bChecked )
{
    if( bChecked == true )
    {
        help_tool_->insertAction( halt_log_act_, clear_log_act_ );
        setView( ACT_HELP_CLEAR_LOG );
    }
    else
    {
        help_tool_->removeAction( clear_log_act_ );
        unsetView( ACT_HELP_CLEAR_LOG );
    }
}

void MainWindow::viewHelpHaltLog( bool bChecked )
{
    if( bChecked == true )
    {
        help_tool_->insertAction( content_act_, halt_log_act_ );
        setView( ACT_HELP_HALT_LOG );
    }
    else
    {
        help_tool_->removeAction( halt_log_act_ );
        unsetView( ACT_HELP_HALT_LOG );
    }
}

void MainWindow::viewHelpContent( bool bChecked )
{
    if( bChecked == true )
    {
        help_tool_->insertAction( about_act_, content_act_ );
        setView( ACT_HELP_CONTENT );
    }
    else
    {
        help_tool_->removeAction( content_act_ );
        unsetView( ACT_HELP_CONTENT );
    }
}

void MainWindow::viewHelpAbout( bool bChecked )
{
    if( bChecked == true )
    {
        help_tool_->addAction( about_act_ );
        setView( ACT_HELP_ABOUT );
    }
    else
    {
        help_tool_->removeAction( about_act_ );
        unsetView( ACT_HELP_ABOUT );
    }
}

void MainWindow::viewSetDefault()
{
    bool bVal = berApplet->yesOrCancelBox( tr( "Would you like to change to the initial toolbar view?"), this, true );
    if( bVal == false ) return;

    berApplet->settingsMgr()->clearViewValue(VIEW_FILE);
    berApplet->settingsMgr()->clearViewValue(VIEW_EDIT);
    berApplet->settingsMgr()->clearViewValue(VIEW_TOOL);
    berApplet->settingsMgr()->clearViewValue(VIEW_CRYPT);
    berApplet->settingsMgr()->clearViewValue(VIEW_SERVICE);
    berApplet->settingsMgr()->clearViewValue(VIEW_PROTO);
    berApplet->settingsMgr()->clearViewValue(VIEW_KMIP);
    berApplet->settingsMgr()->clearViewValue(VIEW_HELP);

    bVal = berApplet->yesOrNoBox(tr("You have changed toolbar settings. Restart to apply it?"), this, false);
    if( bVal == false ) return;

    berApplet->restartApp();
}

void MainWindow::save()
{
    if( file_path_.isEmpty() || file_path_ == "" )
    {
        saveAs();
    }
    else
    {
        if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
        {
            QString strFileName = ttlv_model_->saveNode();
            if( strFileName.length() > 0 )
            {
                file_path_ = strFileName;
                setTitle( file_path_ );
            }
        }
        else
        {
            if( berApplet->yesOrNoBox( tr("Do you want to overwrite %1 as BER file?").arg(file_path_), this ) == 0)
            {
                return;
            }

            const BIN& binBer = ber_model_->getBER();
            JS_BIN_fileWrite( &binBer, file_path_.toLocal8Bit().toStdString().c_str() );
            setTitle( file_path_ );
        }
    }
}

void MainWindow::saveAs()
{
    QString strFileName;

    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
    {
        strFileName = ttlv_model_->saveNode();
    }
    else
    {
        strFileName = ber_model_->SaveNode();
    }

    if( strFileName.length() > 0 )
    {
        file_path_ = strFileName;
        setTitle( file_path_ );
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
        halt_log_act_->setIcon( QIcon( ":/images/log_en.png" ));
        berApplet->messageBox( tr("Start logging"), this );
    }
    else
    {
        log( "Log is halt" );
        log_halt_ = true;
        halt_log_act_->setIcon( QIcon( ":/images/log_halt.png" ));
        berApplet->messageBox( tr("Stop logging"), this );
    }
}

void MainWindow::content()
{
    if( content_ == nullptr )
        content_ = new ContentMain;

    content_->show();
    content_->raise();
    content_->activateWindow();
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
    QString link = "https://github.com/jykim74/BerEditor/discussions";
//    QString link = "https://groups.google.com/g/bereditor";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::useLog( bool bEnable )
{
    text_tab_->setTabEnabled( 1, bEnable );
}

int MainWindow::decodeData( const BIN *pData, const QString strPath )
{
    int ret = 0;
    if( pData == NULL || pData->nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no data"), this );
        return -1;
    }

    ret = openBer( pData );
    file_path_ = strPath;
    setTitle( QString( strPath ));

    return ret;
}

void MainWindow::reloadData()
{
#ifdef OLD_TREE
    ber_model_->parseTree( berApplet->settingsMgr()->autoExpand() );
#else
    ber_model_->makeTree( berApplet->settingsMgr()->autoExpand() );
#endif
}

int MainWindow::decodeTitle( const BIN *pData, const QString strTitle )
{
    int ret = 0;
    if( pData == NULL || pData->nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no data"), this );
        return -1;
    }

    ret = openBer( pData );
    setTitle( QString( strTitle ));

    return ret;
}

int MainWindow::decodeTTLV( const BIN *pData )
{
    if( pData == NULL || pData->nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no data"), this );
        return -1;
    }

    if( JS_KMS_isTTLV( pData ) == 0 )
    {
        berApplet->warningBox( tr( "The data is not TTLV format" ), this );
        return -2;
    }

    ttlv_model_->setTTLV( pData );
    ttlv_model_->parseTree();

    if( hsplitter_->widget(0) != ttlv_model_->getTreeView() )
        hsplitter_->replaceWidget(0, ttlv_model_->getTreeView() );

    setTitle( "TTLV" );
    return 0;
}

void MainWindow::reloadTTLV()
{
    ttlv_model_->parseTree();
    ttlv_model_->getTreeView()->viewRoot();
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
        QString strText;

        if( hsplitter_->widget(0) == ttlv_model_->getTreeView())
            strText = ttlv_model_->getTreeView()->GetTextView();
        else
            strText = ber_model_->getTreeView()->GetTextView();

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
    QString strText;

    if( hsplitter_->widget(0) == ttlv_model_->getTreeView() )
        strText = ttlv_model_->getTreeView()->GetTextView();
    else
        strText = ber_model_->getTreeView()->GetTextView();

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
