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
    QTextEdit* rightText() { return right_text_; };
    QTextEdit* rightXML() { return right_xml_; };
    TTLVTreeView* ttlvTree() { return ttlv_tree_; };
    TTLVTreeModel*ttlvModel() { return ttlv_model_; };

    void showTextMsg( const QString& msg );

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

private slots:
    void newFile();
    void open();
    void openRecent();
    void openCert();
    void openCRL();
    void openCSR();

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
    void insertBER();
    void insertData();
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

    bool log_halt_;
};

#endif // MAINWINDOW_H
