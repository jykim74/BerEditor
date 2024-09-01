/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CAVP_DLG_H
#define CAVP_DLG_H

#include <QDialog>
#include "ui_cavp_dlg.h"

namespace Ui {
class CAVPDlg;
}

class CAVPDlg : public QDialog, public Ui::CAVPDlg
{
    Q_OBJECT

public:
    explicit CAVPDlg(QWidget *parent = nullptr);
    ~CAVPDlg();

private slots:
    void clickRspPathFind();

    void clickECC_ECDSARadio();
    void clickECC_ECDHRadio();
    void clickRSA_ESRadio();
    void clickRSA_PSSRadio();

    void clickSymRun();
    void clickAERun();
    void clickHashRun();
    void clickHMACRun();
    void clickECCRun();
    void clickRSARun();
    void clickDRBGRun();
    void clickDRBGTest();
    void clickPBKDFRun();

    void clickSymFind();
    void clickAEFind();
    void clickHashFind();
    void clickHMACFind();
    void clickECCFind();
    void clickRSAFind();
    void clickDRBGFind();
    void clickPBKDFFind();

    void clickRSADETPriFind();

    void changeECCType(int index);
    void changeRSAType(int index);

    void changeDRBGMethod( int index );
    void changeDRBG2Method( int index );

    void MCTKeyChanged( const QString& text );
    void MCTIVChanged( const QString& text );
    void MCTPTChanged( const QString& text );
    void MCTCTChanged( const QString& text );
    void MCTLastKeyChanged( const QString& text );
    void MCTLastIVChanged( const QString& text );
    void MCTLastPTChanged( const QString& text );
    void MCTLastCTChanged( const QString& text );

    void MCTSHA256SeedChanged( const QString& text );
    void MCTSHA256FirstMDChanged( const QString& text );
    void MCTSHA256LastMDChanged( const QString& text );

    void DRBG2EntropyInputChanged( const QString& text );
    void DRBG2NonceChanged( const QString& text );
    void DRBG2PersonalStringChanged( const QString& text );
    void DRBG2EntropyInputReseedChanged( const QString& text );
    void DRBG2AdditionalInputReseedChanged( const QString& text );
    void DRBG2AdditionalInputChanged( const QString& text );
    void DRBG2AdditionalInput2Changed( const QString& text );
    void DRBG2ReturnedBitsChanged();

    void clickSymMCTRun();
    void clickSymMCTClear();
    void clickHashMCTRun();
    void clickHashMCTClear();

    void clickDRBG2Clear();
    void clickDRBG2Run();

    void clickACVPClear();
    void clickACVPRun();
    void clickACVPThreadRun();
    void clickACVPThreadStop();



    void clickACVP_LDTClear();
    void clickACVP_LDTRun();
    void clickACVP_LDTThreadRun();
    void clickACVP_LDTThreadStop();

    void ACVP_LDTContentChanged( const QString& text );

private:
    void initialize();
    bool isNameValid( const QString strPathName, const QString strVal1, const QString strVal2, const QString strVal3 );
    QString getRspFile(const QString &reqFileName );
    void logRsp( const QString& strLog );

    int makeSymData( const QString strKey, const QString strIV, const QString strPT );

    int makeSymCBC_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo = false );
    int makeSymECB_MCT( const QString strKey, const QString strPT, bool bInfo = false );
    int makeSymCTR_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo = false );
    int makeSymCFB_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo = false );
    int makeSymOFB_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo = false );

    int makeSymDecCBC_MCT( const QString strKey, const QString strIV, const QString strCT, bool bInfo = false );
    int makeSymDecECB_MCT( const QString strKey, const QString strCT, bool bInfo = false );
    int makeSymDecCTR_MCT( const QString strKey, const QString strIV, const QString strCT, bool bInfo = false );
    int makeSymDecCFB_MCT( const QString strKey, const QString strIV, const QString strCT, bool bInfo = false );
    int makeSymDecOFB_MCT( const QString strKey, const QString strIV, const QString strCT, bool bInfo = false );

    int makeAEData( const QString strKey, const QString strIV, const QString strPT, const QString strAAD, int nTagLen );
    int makeADData( const QString strKey, const QString strIV, const QString strCT, const QString strAAD, const QString strTag );
    int makeHashData( int nLen, const QString strVal );
    int makeHashMCT( const QString strAlg, const QString strSeed, bool bInfo = false );
    int makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const QString strKey, const QString strMsg );
    int makePBKDF( int nIteration, const QString strPass, QString strSalt, int nKLen );
    int makeDRBG( const QString strMethod,
                  int nReturnedBitsLen,
                  const QString strAlg,
                  int nDF,
                  int nPR,
                  const QString strEntropyInput,
                  const QString strNonce,
                  const QString strPersonalizationString,
                  const QString strEntropyInputReseed,
                  const QString strAdditionalInputReseed,
                  const QString strAdditionalInput1,
                  const QString strAdditionalInput2,
                  bool bInfo = false );

    int makeRSA_ES_DET( const QString strPri, const QString strC );
    int makeRSA_ES_ENT( int nE, const QString strN, const QString strM );
    int makeRSA_ES_KGT( int nKeyLen, int nE, int nCount );

    int makeRSA_PSS_KPG( int nLen, int nE, int nCount );
    int makeRSA_PSS_SGT( int nE, const QString strPri, const QString strHash, const QString strM );
    int makeRSA_PSS_SVT( int nE, const QString strN, const QString strHash, const QString strM, const QString strS );

    int makeECDH_KPG( const QString strParam, int nCount );
    int makeECDH_PKV( const QString strParam, const QString strPubX, const QString strPubY );
    int makeECDH_KAKAT( const QString strParam, const QString strRA, const QString strRB, const QString strKTA1X, const QString strKTA1Y );

    int makeECDSA_KPG( const QString strParam, int nNum );
    int makeECDSA_PKV( const QString strParam, const QString strYX, const QString strYY );
    int makeECDSA_SGT( const QString strParam, const QString strHash, const QString strM );
    int makeECDSA_SVT( const QString strParam, const QString strHash, const QString strM, const QString strYX, const QString strYY, const QString strR, const QString strS );

private:
    QString rsp_name_;
};

#endif // CAVP_DLG_H
