#ifndef MAKE_PRI_KEY_DLG_H
#define MAKE_PRI_KEY_DLG_H

#include <QDialog>
#include "ui_make_pri_key_dlg.h"
#include "js_bin.h"

const int RSA_IDX = 0;
const int ECC_IDX = 1;
const int DSA_IDX = 2;
const int RAW_IDX = 3;

namespace Ui {
class MakePriKeyDlg;
}

class MakePriKeyDlg : public QDialog, public Ui::MakePriKeyDlg
{
    Q_OBJECT

public:
    explicit MakePriKeyDlg(QWidget *parent = nullptr);
    ~MakePriKeyDlg();

private slots:
    void changeRSA_N();
    void changeRSA_E( const QString& text );
    void changeRSA_D();
    void changeRSA_P( const QString& text );
    void changeRSA_Q( const QString& text );
    void changeRSA_DMP1( const QString& text );
    void changeRSA_DMQ1( const QString& text );
    void changeRSA_IQMP( const QString& text );

    void changeECC_PubX();
    void changeECC_PubY();
    void changeECC_Private();
    void changeECC_CurveSN();

    void changeDSA_G();
    void changeDSA_P();
    void changeDSA_Q( const QString& text );
    void changeDSA_Public();
    void changeDSA_Private( const QString& text );

    void changeRawPublic();
    void changeRawPrivate();
    void changeRawName();

    void clickExport();
    void clickMake();
    void clickClearAll();

    void changeTab( int index );
    void changeAlg( int index );
    void checkPublicKey();

    void clickDecode();
    void clickCheckKeyPair();
    void clickCheckPubKey();
    void clickSaveToKeyPairMan();

private:
    void initUI();
    void initialize();

    void setEnableRSA_N( bool bVal );
    void setEnableRSA_E( bool bVal );
    void setEnableRSA_D( bool bVal );
    void setEnableRSA_P( bool bVal );
    void setEnableRSA_Q( bool bVal );
    void setEnableRSA_DMP1( bool bVal );
    void setEnableRSA_DMQ1( bool bVal );
    void setEnableRSA_IQMP( bool bVal );

    void setEnableECC_Private( bool bVal );
    void setEnableECC_PubX( bool bVal );
    void setEnableECC_PubY( bool bVal );

    void setEnableDSA_P( bool bVal );
    void setEnableDSA_Q( bool bVal );
    void setEnableDSA_G( bool bVal );
    void setEnableDSA_Private( bool bVal );
    void setEnableDSA_Public( bool bVal );

    void setEnableRawPublic( bool bVal );
    void setEnableRawPrivate( bool bVal );

    void clearRSA();
    void clearECC();
    void clearDSA();
    void clearRaw();

    int getRSA( BIN *pRSA, bool bPri = false );
    int getECC( BIN *pECC, bool bPri = false );
    int getDSA( BIN *pDSA, bool bPri = false );
    int getRaw( BIN *pRaw, bool bPri = false );
};

#endif // MAKE_PRI_KEY_DLG_H
