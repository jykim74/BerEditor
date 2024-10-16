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

#include "ber_model.h"
#include "ber_tree_view.h"
#include "ttlv_tree_model.h"
#include "ttlv_tree_view.h"
#include "js_bin.h"

class QPrinter;

class KeyManDlg;
class GenHashDlg;
class GenMacDlg;
class EncDecDlg;
class SignVerifyDlg;
class PubEncDecDlg;
class KeyAgreeDlg;
class CMSDlg;
class SSSDlg;
class CertPVDDlg;
class GenOTPDlg;
class CAVPDlg;
class SSLVerifyDlg;
class VIDDlg;
class BNCalcDlg;
class KeyPairManDlg;
class OCSPClientDlg;
class TSPClientDlg;
class CMPClientDlg;
class SCEPClientDlg;
class CertManDlg;
class TTLVEncoderDlg;
class TTLVClientDlg;
class ContentMain;

namespace Ui {
class MainWindow;
}

enum {
    TABLE_IDX_HEX = 0,
    TABLE_IDX_XML = 1,
    TABLE_IDX_TXT = 2
};

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
    QTextEdit* rightText() { return right_text_; };
    QTextEdit* rightXML() { return right_xml_; };
    TTLVTreeView* ttlvTree() { return ttlv_tree_; };
    TTLVTreeModel* ttlvModel() { return ttlv_model_; };
    BerModel* berModel() { return ber_model_; };

    void showTextMsg( const QString& msg );
    int tableCurrentIndex();

    void showWindow();
    void openBer( const BIN *pBer );
    bool isChanged();

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void infoClear();

    QString getInfo();
    void useLog( bool bEnable = true );

    void decodeData( const BIN *pData, const QString strPath = "" );
    void decodeTTLV( const BIN *pData );
    bool isTTLV();

    void runSignVerify( bool bSign, bool bEncPri, const QString strPriPath, const QString strCertPath );
    void runPubEncDec( bool bEnc, bool bEncPri, const QString strPriPath, const QString strCertPath );

    void viewToolBar();

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
    void certPVD();
    void CAVP();
    void sslVerify();
    void genOTP();
    void VID();
    void BNCalc();
    void keyPairMan();
    void ocspClient();
    void tspClient();
    void cmpClient();
    void scepClient();
    void certMan();
    void runMakeBER();
    void runDecodeData();
    void runDecodeTTLV();
    void runMakeTTLV();
    void ttlvClient();
    void ttlvEncoder();
    void numTrans();
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
    void createActions();
    void createStatusBar();
    void createCryptoDlg();

    void createTableMenu();
    int berFileOpen( const QString berPath );
    void setTitle( const QString strName );

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();


    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    BerTreeView     *left_tree_;
    BerModel        *ber_model_;

    TTLVTreeView    *ttlv_tree_;
    TTLVTreeModel   *ttlv_model_;

    QTabWidget      *table_tab_;
    QTabWidget      *text_tab_;
    QTextEdit       *log_text_;
    QTextEdit       *info_text_;

    QTableWidget    *right_table_;
    QTextEdit       *right_text_;
    QTextEdit       *right_xml_;
    QString          file_path_;

    // Cryptogram dlg
    KeyManDlg       *key_man_dlg_;
    GenHashDlg      *gen_hash_dlg_;
    GenMacDlg       *gen_mac_dlg_;
    EncDecDlg       *enc_dec_dlg_;
    SignVerifyDlg   *sign_verify_dlg_;
    PubEncDecDlg    *pub_enc_dec_dlg_;
    KeyAgreeDlg     *key_agree_dlg_;
    CMSDlg          *cms_dlg_;
    SSSDlg          *sss_dlg_;
    CertPVDDlg      *cert_pvd_dlg_;
    GenOTPDlg       *gen_otp_dlg_;
    CAVPDlg         *cavp_dlg_;
    SSLVerifyDlg    *ssl_verify_dlg_;
    VIDDlg          *vid_dlg_;
    BNCalcDlg       *bn_calc_dlg_;
    KeyPairManDlg   *key_pair_man_dlg_;
    OCSPClientDlg   *ocsp_client_dlg_;
    TSPClientDlg    *tsp_client_dlg_;
    CMPClientDlg    *cmp_client_dlg_;
    SCEPClientDlg   *scep_client_dlg_;
    CertManDlg      *cert_man_dlg_;
    TTLVEncoderDlg  *ttlv_encoder_dlg_;
    TTLVClientDlg   *ttlv_client_dlg_;
    ContentMain     *content_;

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

    QToolBar* tool_tool_;
    QAction* data_encode_act_;
    QAction* num_trans_act_;
    QAction* oid_act_;
    QAction* make_ber_act_;
    QAction* decode_data_act_;
    QAction* get_uri_act_;

    QToolBar* crypt_tool_;
    QAction* key_man_act_;
    QAction* hash_act_;
    QAction* mac_act_;
    QAction* enc_dec_act_;
    QAction* sign_verify_act_;
    QAction* pub_enc_dec_act_;
    QAction* key_agree_act_;
    QAction* cms_act_;
    QAction* sss_act_;
    QAction* cert_pvd_act_;
    QAction* gen_otp_act_;
    QAction* vid_act_;
    QAction* calc_act_;
    QAction* key_pair_man_act_;
    QAction* cert_man_act_;
    QAction* cavp_act_;
    QAction* ssl_act_;

    QToolBar* proto_tool_;
    QAction* ocsp_act_;
    QAction* tsp_act_;
    QAction* cmp_act_;
    QAction* scep_act_;

    QToolBar* kmip_tool_;
    QAction* ttlv_decode_act_;
    QAction* ttlv_make_act_;
    QAction* ttlv_encode_act_;
    QAction* ttlv_client_act_;

    QToolBar* help_tool_;
    QAction* setting_act_;
    QAction* clear_act_;
    QAction* log_act_;
    QAction* content_act_;
    QAction* lcn_act_;
    QAction* bug_issue_act_;
    QAction* qna_act_;
    QAction* about_act_;

    bool log_halt_;
};

#endif // MAINWINDOW_H
