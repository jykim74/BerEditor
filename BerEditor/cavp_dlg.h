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
    void clickPBKDFRun();

    void clickSymFind();
    void clickAEFind();
    void clickHashFind();
    void clickHMACFind();
    void clickECCFind();
    void clickRSAFind();
    void clickDRBGFind();
    void clickPBKDFFind();

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

private:
    void initialize();
    QString getRspFile(const QString &reqFileName );
    int makeSymData( const QString strKey, const QString strIV, const QString strPT );
    int makeAEData( const QString strKey, const QString strIV, const QString strPT, const QString strAAD, int nTagLen );
    int makeADData( const QString strKey, const QString strIV, const QString strCT, const QString strAAD, const QString strTag );
    int makeHashData( int nLen, const QString strVal );
    int makeHashMCT( const QString strSeed );
    int makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const QString strKey, const QString strMsg );
    int makePBKDF( int nIteration, const QString strPass, QString strSalt, int nKLen );
    int makeDRBG( int nReturnedBitsLen,
                  const QString strEntropyInput,
                  const QString strNonce,
                  const QString strPersonalizationString,
                  const QString strEntropyInputReseed,
                  const QString strAdditionalInputReseed,
                  const QString strAdditionalInput1,
                  const QString strAdditionalInput2 );
};

#endif // CAVP_DLG_H
