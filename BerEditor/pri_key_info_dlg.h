/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PRI_KEY_INFO_DLG_H
#define PRI_KEY_INFO_DLG_H

#include "js_bin.h"
#include <QDialog>
#include "ui_pri_key_info_dlg.h"

namespace Ui {
class PriKeyInfoDlg;
}

class PriKeyInfoDlg : public QDialog, public Ui::PriKeyInfoDlg
{
    Q_OBJECT

public:
    explicit PriKeyInfoDlg(QWidget *parent = nullptr);
    ~PriKeyInfoDlg();

    void setPrivateKey( const BIN *pPriKey, const QString strTitle = "" );
    void setPublicKey( const BIN *pPubKey, const QString strTitle = "" );

    void setPrivateKeyPath( const QString strPriKeyPath );
    void setPublicKeyPath( const QString strPubKeyPath );

    void readPrivateKey( BIN *pPriKey );
    void readPublicKey( BIN *pPubKey );

private slots:
    void showEvent(QShowEvent *event);

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

    void changeDSA_G();
    void changeDSA_P();
    void changeDSA_Q( const QString& text );
    void changeDSA_Public();
    void changeDSA_Private( const QString& text );

    void changeRawPublic();
    void changeRawPrivate();

    void clearAll();
    void clickDecode();
    void clickCheckPubKey();

    void clickSavePriKey();
    void clickSavePubKey();
    void clickCheckKeyPair();
    void clickApplyChange();
    void checkEditMode();

private:
    void setTitle( bool bPri, const QString strName = "" );

    void initialize();
    bool isChanged();

    void setRSAKey( const BIN *pKey, bool bPri = true );
    void setECCKey( const BIN *pKey, bool bPri = true );
    void setDSAKey( const BIN *pKey, bool bPri = true );
    void setRawKey( const BIN *pKey, bool bPri = true );

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

    void setModeUI( bool bVal );

    BIN pri_key_;
    BIN pub_key_;
    int key_type_;
    QString key_path_;
};

#endif // PRI_KEY_INFO_DLG_H
