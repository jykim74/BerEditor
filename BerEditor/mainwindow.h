/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextBrowser>
#include <QList>
#include <QPlainTextEdit>

#include "ber_model.h"
#include "ber_tree_view.h"
#include "ttlv_tree_model.h"
#include "ttlv_tree_view.h"
#include "js_bin.h"
#include "common.h"
#include "code_editor.h"
#include "highlighter_xml.h"

class QPrinter;

class KeyManDlg;
class GenHashDlg;
class GenMacDlg;
class EncDecDlg;
class SignVerifyDlg;
class PubEncDecDlg;
class KeyAgreeDlg;
class PKCS7Dlg;
class SSSDlg;
class CertPVDDlg;
class GenOTPDlg;
class CAVPDlg;
class SSLCheckDlg;
class VIDDlg;
class BNCalcDlg;
class KeyPairManDlg;
class OCSPClientDlg;
class TSPClientDlg;
class CMPClientDlg;
class SCEPClientDlg;
class ACMEClientDlg;
class CertManDlg;
class TTLVEncoderDlg;
class TTLVClientDlg;
class ContentMain;
class FindDlg;
class KeyListDlg;
class X509CompareDlg;
class DocSignerDlg;
class MakePriKeyDlg;
class BERCompareDlg;

namespace Ui {
class MainWindow;
}

enum {
    TABLE_IDX_HEX = 0,
    TABLE_IDX_XML = 1,
    TABLE_IDX_TXT = 2,
    TABLE_IDX_JSON = 3
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void initialize();
    void loadFile( const QString &filename );
    QPlainTextEdit* logText() { return log_text_; };
    CodeEditor* infoText() { return info_text_; };
    QTableWidget* rightTable() { return right_table_; };
    CodeEditor* rightText() { return right_text_; };
    CodeEditor* rightXML() { return right_xml_; };
    CodeEditor* rightJSON() { return right_json_; };

    BerModel* berModel() { return ber_model_; };
    TTLVTreeModel* ttlvModel() { return ttlv_model_; };

    void showTextMsg( const QString& msg );
    int tableCurrentIndex();

    void showWindow();
    int openBer( const BIN *pBer );
    bool isChanged();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void infoClear();

    QString getInfo();
    void useLog( bool bEnable = true );

    int decodeData( const BIN *pData, const QString strPath = "" );
    int decodeTitle( const BIN *pData, const QString strTitle = "" );
    void reloadData();

    int decodeTTLV( const BIN *pData );
    void reloadTTLV();
    bool isTTLV();

    void runSignVerify( bool bSign, bool bEncPri, const QString strPriPath, const QString strCertPath );
    void runPubEncDec( bool bEnc, bool bEncPri, const QString strPriPath, const QString strCertPath );
    void runBERCompare( const BIN *pA, const BIN *pB );

    void viewFileNew( bool bChecked );
    void viewFileOpen( bool bChecked );
    void viewFileOpenCert( bool bChecked );
    void viewFileOpenCRL( bool bChecked );
    void viewFileOpenCSR( bool bChecked );
    void viewFileOpenPriKey( bool bChecked );
    void viewFileOpenPubKey( bool bChecked );
    void viewFileOpenCMS( bool bChecked );
    void viewFileSave( bool bChecked );
    void viewFilePrint( bool bChecked );

    void viewEditExpandAll( bool bChecked );
    void viewEditExpandNode( bool bChecked );
    void viewEditCollapseAll( bool bChecked );
    void viewEditCollapseNode( bool bChecked );
    void viewEditPrev( bool bChecked );
    void viewEditNext( bool bChecked );
    void viewEditFindNode( bool bChecked );

    void viewToolDataConverter( bool bChecked );
    void viewToolNumConverter( bool bChecked );
    void viewToolOIDInfo( bool bChecked );
    void viewToolMakeBER( bool bChecked );
    void viewToolBERCheck( bool bChecked );
    void viewToolDecodeData( bool bChecked );
    void viewToolGetURI( bool bChecked );
    void viewToolBERCompare( bool bChecked );

    void viewCryptKeyMan( bool bChecked );
    void viewCryptHash( bool bChecked );
    void viewCryptMAC( bool bChecked );
    void viewCryptEncDec( bool bChecked );
    void viewCryptSignVerify( bool bChecked );
    void viewCryptPubEnc( bool bChecked );
    void viewCryptKeyAgree( bool bChecked );
    void viewCryptPKCS7( bool bChecked );
    void viewCryptSSS( bool bChecked );
    void viewCryptCertPVD( bool bChecked );
    void viewCryptOTPGen( bool bChecked );
    void viewCryptVID( bool bChecked );
    void viewCryptBNCalc( bool bChecked );
    void viewCryptMakePri( bool bChecked );

    void viewServiceKeyPairMan( bool bChecked );
    void viewServiceCertMan( bool bChecked );
    void viewServiceKeyList( bool bChecked );
    void viewServiceCAVP( bool bChecked );
    void viewServiceSSLCheck( bool bChecked );
    void viewServiceX509Comp( bool bChecked );
    void viewServiceDocSigner( bool bChecked );

    void viewProtoOCSP( bool bChecked );
    void viewProtoTSP( bool bChecked );
    void viewProtoCMP( bool bChecked );
    void viewProtoSCEP( bool bChecked );
    void viewProtoACME( bool bChecked );

    void viewKMIPDecodeTTLV( bool bChecked );
    void viewKMIPMakeTTLV( bool bChecked );
    void viewKMIPEncodeTTLV( bool bChecked );
    void viewKMIPClientTTLV( bool bChecked );

    void viewHelpSettings( bool bChecked );
    void viewHelpClearLog( bool bChecked );
    void viewHelpHaltLog( bool bChecked );
    void viewHelpContent( bool bChecked );
    void viewHelpAbout( bool bChecked );

    void viewSetDefault();

    void mac2( const QString strKey, const QString strIV );
    void encDec2( const QString strKey, const QString strIV );

private slots:
    void changeTableTab();

    void newFile();
    void open();
    void openRecent();
    void openCert();
    void openCRL();
    void openCSR();
    void openPriKey();
    void openPubKey();
    void openCMS();

    void copy();
    void copyAsHex();
    void copyAsBase64();
    void treeExpandAll();
    void treeExpandNode();
    void treeCollapseAll();
    void treeCollapseNode();
    void prevNode();
    void nextNode();
    void findNode();

    void about();
    void setting();
    void test();
    void dataConvert();
    void keyManage();
    void hash();
    void mac();

    void makePriKey();
    void keyAgree();
    void oidInfo();
    void encDec();
    void BERCompare();

    void signVerify();
    void pubEncDec();
    void pkcs7();
    void sss();
    void certPVD();
    void CAVP();
    void sslCheck();
    void x509Compare();
    void docSigner();
    void genOTP();
    void VID();
    void BNCalc();
    void keyPairMan();
    void ocspClient();
    void tspClient();
    void cmpClient();
    void scepClient();
    void acmeClient();
    void certMan();
    void keyList();
    void runMakeBER();
    void runDecodeData();
    void runDecodeTTLV();
    void runMakeTTLV();
    void runBERCheck();
    void ttlvClient();
    void ttlvEncoder();
    void numConverter();
    void getURI();
    void save();
    void saveAs();
    void clearLog();
    void toggleLog();
    void content();
    void licenseInfo();

    void bugIssueReport();
    void qnaDiscussion();

    void print();
    void printPreview(QPrinter *printer);
    void filePrintPreview();
    void quit();

    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event );
    void closeEvent(QCloseEvent *event);

    void rightTableCustomMenu( const QPoint& pos );
    void rightTableCopy();
    void rightTableSelectAll();
    void rightTableUnselectAll();

private:
    void createFileActions();
    void createEditActions();
    void createToolActions();
    void createCryptographyActions();
    void createServiceActions();
    void createProtocolActions();
    void createKMIPActions();
    void createHelpActions();

    void createActions();
    void createViewActions();
    void createStatusBar();
    void createCryptoDlg();

    void createTableMenu();
    int berFileOpen( const QString berPath );
    void setTitle( const QString strName );

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();

    bool isView( int nAct );
    void setView( int nAct );
    void unsetView( int nAct );

    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    BerModel        *ber_model_;
    TTLVTreeModel   *ttlv_model_;

    QTabWidget      *table_tab_;
    QTabWidget      *text_tab_;
    QPlainTextEdit  *log_text_;
    CodeEditor       *info_text_;

    QTableWidget    *right_table_;

    CodeEditor       *right_text_;
    CodeEditor       *right_xml_;
    CodeEditor       *right_json_;
    QString          file_path_;

    // Cryptogram dlg
    KeyManDlg       *key_man_dlg_ = nullptr;
    GenHashDlg      *gen_hash_dlg_ = nullptr;
    GenMacDlg       *gen_mac_dlg_ = nullptr;
    EncDecDlg       *enc_dec_dlg_ = nullptr;
    SignVerifyDlg   *sign_verify_dlg_ = nullptr;
    PubEncDecDlg    *pub_enc_dec_dlg_ = nullptr;
    KeyAgreeDlg     *key_agree_dlg_ = nullptr;
    PKCS7Dlg        *pkcs7_dlg_ = nullptr;
    SSSDlg          *sss_dlg_ = nullptr;
    CertPVDDlg      *cert_pvd_dlg_ = nullptr;
    GenOTPDlg       *gen_otp_dlg_ = nullptr;
    CAVPDlg         *cavp_dlg_ = nullptr;
    SSLCheckDlg     *ssl_check_dlg_ = nullptr;
    VIDDlg          *vid_dlg_ = nullptr;
    BNCalcDlg       *bn_calc_dlg_ = nullptr;
    KeyPairManDlg   *key_pair_man_dlg_ = nullptr;
    OCSPClientDlg   *ocsp_client_dlg_ = nullptr;
    TSPClientDlg    *tsp_client_dlg_ = nullptr;
    CMPClientDlg    *cmp_client_dlg_ = nullptr;
    SCEPClientDlg   *scep_client_dlg_ = nullptr;
    ACMEClientDlg   *acme_client_dlg_ = nullptr;
    CertManDlg      *cert_man_dlg_ = nullptr;
    TTLVEncoderDlg  *ttlv_encoder_dlg_ = nullptr;
    TTLVClientDlg   *ttlv_client_dlg_ = nullptr;
    ContentMain     *content_ = nullptr;
    FindDlg         *find_dlg_ = nullptr;
    KeyListDlg      *key_list_dlg_ = nullptr;
    X509CompareDlg  *x509_comp_dlg_ = nullptr;
    DocSignerDlg    *doc_signer_dlg_ = nullptr;
    MakePriKeyDlg   *make_pri_key_dlg_ = nullptr;
    BERCompareDlg   *ber_comp_dlg_ = nullptr;

    QToolBar* file_tool_;
    QAction* new_act_;
    QAction* open_act_;
    QAction* open_cert_act_;
    QAction* open_crl_act_;
    QAction* open_csr_act_;
    QAction* open_pri_key_act_;
    QAction* open_pub_key_act_;
    QAction* open_cms_act_;
    QAction* save_act_;
    QAction* save_as_act_;
    QAction* print_act_;
    QAction* print_pre_act_;
    QAction* quit_act_;

    QToolBar* edit_tool_;
    QAction* copy_act_;
    QAction* copy_as_hex_act_;
    QAction* copy_as_base64_act_;
    QAction* expand_all_act_;
    QAction* expand_node_act_;
    QAction* collapse_all_act_;
    QAction* collapse_node_act_;
    QAction* prev_act_;
    QAction* next_act_;
    QAction* find_node_act_;

    QToolBar* tool_tool_;
    QAction* data_encode_act_;
    QAction* num_converter_act_;
    QAction* oid_act_;
    QAction* make_ber_act_;
    QAction* ber_check_act_;
    QAction* decode_data_act_;
    QAction* get_uri_act_;
    QAction* ber_compare_act_;

    QToolBar* crypt_tool_;
    QAction* key_man_act_;
    QAction* hash_act_;
    QAction* mac_act_;
    QAction* enc_dec_act_;
    QAction* sign_verify_act_;
    QAction* pub_enc_dec_act_;
    QAction* key_agree_act_;
    QAction* pkcs7_act_;
    QAction* sss_act_;
    QAction* cert_pvd_act_;
    QAction* gen_otp_act_;
    QAction* vid_act_;
    QAction* calc_act_;
    QAction* make_pri_act_;

    QToolBar* service_tool_;
    QAction* key_pair_man_act_;
    QAction* cert_man_act_;
    QAction* key_list_act_;
    QAction* cavp_act_;
    QAction* ssl_act_;
    QAction* x509_comp_act_;
    QAction* doc_signer_act_;

    QToolBar* proto_tool_;
    QAction* ocsp_act_;
    QAction* tsp_act_;
    QAction* cmp_act_;
    QAction* scep_act_;
    QAction* acme_act_;

    QToolBar* kmip_tool_;
    QAction* ttlv_decode_act_;
    QAction* ttlv_make_act_;
    QAction* ttlv_encode_act_;
    QAction* ttlv_client_act_;

    QToolBar* help_tool_;
    QAction* setting_act_;
    QAction* clear_log_act_;
    QAction* halt_log_act_;
    QAction* content_act_;
    QAction* lcn_act_;
    QAction* bug_issue_act_;
    QAction* qna_act_;
    QAction* about_act_;

    bool log_halt_;
};

#endif // MAINWINDOW_H
