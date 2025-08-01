#include <QElapsedTimer>

#include "common.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "bn_calc_dlg.h"
#include "js_bn.h"
#include "ber_applet.h"

#include "openssl/bn.h"
#include "openssl/err.h"

#include <QRegExpValidator>
#include <QClipboard>

const QString kAdd = "A + B";
const QString kSub = "A - B";
const QString kMul = "A * B";
const QString kDiv = "A / B";
const QString kExp = "A ^ B";
const QString kSqr = "A ^ 2";
const QString kMod = "A % B";
const QString kGcd = "GCD(A,B)";
const QString kOr = "A or B";
const QString kAnd = "A and B";
const QString kXor = "A xor B";
const QString kComp = "A comp";
const QString kShr = "A >>";
const QString kShl = "A <<";
const QString kInv = "A^-1";
const QString kSqrt = "√ A";

const QString kAddMod = "(A+B) Mod M";
const QString kSubMod = "(A-B) Mod M";
const QString kMulMod = "(A*B) Mod M";
const QString kDivMod = "(A/B) Mod M";
const QString kExpMod = "(A^B) Mod M";
const QString kSqrMod = "(A^2) Mod M";
const QString kShlMod = "A << Mod M";
const QString kInvMod = "A^-1 Mod M";
const QString kSqrtMod = "√ A Mod M";

const QString kNumber = "Number";
const QString kModular = "Modular";
const QString kGF2m = "GF2m";

const QStringList kBitType = { "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "3072", "4096" };
//const QStringList kGroupList = { "Number", "Modular", "GF2m" };
const QStringList kGroupList = { kNumber, kModular, kGF2m };



BNCalcDlg::BNCalcDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mBaseGroupCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBaseGroup(int)));

    connect( mBinCheck, SIGNAL(clicked()), this, SLOT(clickBinary()));
    connect( mDecCheck, SIGNAL(clicked()), this, SLOT(clickDecimal()));
    connect( mHexCheck, SIGNAL(clicked()), this, SLOT(clickHex()));

    connect( mAGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickAGenPrime()));
    connect( mBGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickBGenPrime()));
    connect( mModGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickModGenPrime()));

    connect( mAIsPrimeBtn, SIGNAL(clicked()), this, SLOT(clickAIsPrime()));
    connect( mBIsPrimeBtn, SIGNAL(clicked()), this, SLOT(clickBIsPrime()));
    connect( mModChecPrimeBtn, SIGNAL(clicked()), this, SLOT(clickModIsPrime()));

    connect( mADDBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mSUBBtn, SIGNAL(clicked()), this, SLOT(clickSub()));
    connect( mMULBtn, SIGNAL(clicked()), this, SLOT(clickMultiple()));
    connect( mDIVBtn, SIGNAL(clicked()), this, SLOT(clickDiv()));
    connect( mSQRBtn, SIGNAL(clicked()), this, SLOT(clickSqr()));
    connect( mEXPBtn, SIGNAL(clicked()), this, SLOT(clickExp()));

    connect( mMODBtn, SIGNAL(clicked()), this, SLOT(clickMod()));
    connect( mGCDBtn, SIGNAL(clicked()), this, SLOT(clickGcd()));
    connect( mORBtn, SIGNAL(clicked()), this, SLOT(clickOr()));
    connect( mANDBtn, SIGNAL(clicked()), this, SLOT(clickAnd()));
    connect( mXORBtn, SIGNAL(clicked()), this, SLOT(clickXor()));
    connect( mCOMPBtn, SIGNAL(clicked()), this, SLOT(clickComp()));
    connect( mSHRBtn, SIGNAL(clicked()), this, SLOT(clickShr()));
    connect( mSHLBtn, SIGNAL(clicked()), this, SLOT(clickShl()));
    connect( mINVBtn, SIGNAL(clicked()), this, SLOT(clickInv()));
    connect( mSQRTBtn, SIGNAL(clicked()), this, SLOT(clickSqrt()));

    connect( mAClearBtn, SIGNAL(clicked()), this, SLOT(clearA()));
    connect( mBClearBtn, SIGNAL(clicked()), this, SLOT(clearB()));
    connect( mModClearBtn, SIGNAL(clicked()), this, SLOT(clearMod()));
    connect( mResClearBtn, SIGNAL(clicked()), this, SLOT(clearRes()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clearAll()));

    connect( mAText, SIGNAL(textChanged()), this, SLOT(changeA()));
    connect( mBText, SIGNAL(textChanged()), this, SLOT(changeB()));
    connect( mModText, SIGNAL(textChanged()), this, SLOT(changeMod()));
    connect( mResText, SIGNAL(textChanged()), this, SLOT(changeRes()));

    connect( mACopyBtn, SIGNAL(clicked()), this, SLOT(clickACopy()));
    connect( mAPasteBtn, SIGNAL(clicked()), this, SLOT(clickAPaste()));
    connect( mBCopyBtn, SIGNAL(clicked()), this, SLOT(clickBCopy()));
    connect( mBPasteBtn, SIGNAL(clicked()), this, SLOT(clickBPaste()));
    connect( mModCopyBtn, SIGNAL(clicked()), this, SLOT(clickModCopy()));
    connect( mModPasteBtn, SIGNAL(clicked()), this, SLOT(clickModPaste()));
    connect( mResCopyBtn, SIGNAL(clicked()), this, SLOT(clickResCopy()));

    connect( mResSendABtn, SIGNAL(clicked()), this, SLOT(clickResSendA()));
    connect( mResSendBBtn, SIGNAL(clicked()), this, SLOT(clickResSendB()));
    connect( mResSendModBtn, SIGNAL(clicked()), this, SLOT(clickResSendMod()));

    connect( mAAddOneBtn, SIGNAL(clicked()), this, SLOT(addOneA()));
    connect( mBAddOneBtn, SIGNAL(clicked()), this, SLOT(addOneB()));
    connect( mModAddOneBtn, SIGNAL(clicked()), this, SLOT(addOneMod()));

    connect( mASubOneBtn, SIGNAL(clicked()), this, SLOT(subOneA()));
    connect( mBSubOneBtn, SIGNAL(clicked()), this, SLOT(subOneB()));
    connect( mModSubOneBtn, SIGNAL(clicked()), this, SLOT(subOneMod()));

    connect( mResTimeClearBtn, SIGNAL(clicked()), this, SLOT(clearTime()));
    connect( mSumTimeClearBtn, SIGNAL(clicked()), this, SLOT(clearSum()));
    connect( mAddSumBtn, SIGNAL(clicked()), this, SLOT(clickAddSum()));
    connect( mSubSumBtn, SIGNAL(clicked()), this, SLOT(clickSubSum()));

    connect( mTestBtn, SIGNAL(clicked()), this, SLOT(clickTest()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    int margin = 1;
    int space = 1;

    mAGroup->layout()->setSpacing(space);
    mBGroup->layout()->setSpacing(space);
    mModGroup->layout()->setSpacing(space);
    mAGroup->layout()->setMargin(margin);
    mBGroup->layout()->setMargin(margin);
    mModGroup->layout()->setMargin(margin);

    mAClearBtn->setFixedWidth(38);
    mBClearBtn->setFixedWidth(38);
    mModClearBtn->setFixedWidth(38);
    mResClearBtn->setFixedWidth(38);

    mAAddOneBtn->setFixedWidth(38);
    mBAddOneBtn->setFixedWidth(38);
    mModAddOneBtn->setFixedWidth(38);

    mASubOneBtn->setFixedWidth(38);
    mBSubOneBtn->setFixedWidth(38);
    mModSubOneBtn->setFixedWidth(38);

    mAddSumBtn->setFixedWidth(60);
    mSubSumBtn->setFixedWidth(60);
    mResTimeClearBtn->setFixedWidth(34);
    mSumTimeClearBtn->setFixedWidth(34);

    resize(minimumSizeHint().width(), minimumSizeHint().height() - 70);
#else
    resize(minimumSizeHint().width(), minimumSizeHint().height());
#endif
    intialize();
}

BNCalcDlg::~BNCalcDlg()
{

}

void BNCalcDlg::intialize()
{
    mHexCheck->click();

    mBaseGroupCombo->addItems( kGroupList );

    mAPrimeBitsCombo->addItems(kBitType);
    mBPrimeBitsCombo->addItems(kBitType);
    mModPrimeBitsCombo->addItems( kBitType );

    mAPrimeBitsCombo->setEditable(true);
    mBPrimeBitsCombo->setEditable(true);

#if defined(QT_DEBUG)
    mTestBtn->show();
#else
    mTestBtn->hide();
#endif

    mCloseBtn->setDefault(true);
}


int BNCalcDlg::getInput( BIN *pA, BIN *pB, BIN *pMod )
{
    int nNum = 0;

    QString strA;
    QString strB;
    QString strMod;

    if( pA != NULL )
    {
        strA = mAText->toPlainText().simplified();

        if( strA.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter A" ), this );
            mAText->setFocus();
            return -1;
        }
    }

    if( pB != NULL )
    {
        strB = mBText->toPlainText().simplified();

        if( strB.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter B" ), this );
            mBText->setFocus();
            return -1;
        }
    }

    if( pMod != NULL )
    {
        strMod = mModText->toPlainText().simplified();

        if( strMod.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter M" ), this );
            mModText->setFocus();
            return -1;
        }
    }

    if( mBinCheck->isChecked() )
        nNum = 2;
    else if( mDecCheck->isChecked() )
        nNum = 10;
    else
        nNum = 16;

    if( nNum == 16 )
    {
        if( (strA.length() > 0) && (strA.length() % 2) )
        {
            strA = QString( "0%1").arg( strA );
        }

        if( (strB.length() > 0) && (strB.length() % 2) )
        {
            strB = QString( "0%1").arg( strB );
        }

        if( (strMod.length() > 0) && (strMod.length() % 2) )
        {
            strMod = QString( "0%1").arg( strMod );
        }
    }

    if( strA.length() > 0 )
    {
        if( isValidNumFormat( strA, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The A value have wrong character ( valid characters : %1 )" ).arg( validChars()), this );
            mAText->setFocus();
            return -1;
        }

        getBIN( strA, pA );
    }

    if( strB.length() > 0 )
    {
        if( isValidNumFormat( strB, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The B value have wrong character ( valid characters : %1 )" ).arg( validChars()), this );
            mBText->setFocus();
            return -2;
        }

        getBIN( strB, pB );
    }

    if( strMod.length() > 0 )
    {
        if( isValidNumFormat( strMod, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The M value have wrong character ( valid characters : %1 )" ).arg( validChars()), this );
            mModText->setFocus();
            return -3;
        }

        getBIN( strMod, pMod );
    }

    return 0;
}

const QString BNCalcDlg::getOutput( const BIN *pBin )
{
    QString strValue;

    if( pBin == NULL || pBin->nLen <= 0 )
    {
        strValue.clear();
        return strValue;
    }

    if( mBinCheck->isChecked() )
    {
        char *pBitString = NULL;
        JS_PKI_binToBit( pBin, &pBitString );
        strValue = pBitString;
        if( pBitString ) JS_free( pBitString );
    }
    else if( mDecCheck->isChecked() )
    {
        char *pString = NULL;
        JS_PKI_binToDecimalUnsign( pBin, &pString );
        strValue = pString;
        if( pString ) JS_free( pString );
    }
    else
    {
        strValue = getHexString( pBin );
    }

    return strValue;
}

const QString BNCalcDlg::validChars()
{
    if( mBinCheck->isChecked() )
        return kBinaryChars;
    else if( mDecCheck->isChecked() )
        return kDecimalChars;
    else
        return kHexChars;
}

void BNCalcDlg::getBIN( const QString strValue, BIN *pBin )
{
    if( mBinCheck->isChecked() )
    {
        JS_PKI_bitToBin( strValue.toStdString().c_str(), pBin );
    }
    else if( mDecCheck->isChecked() )
    {
        JS_PKI_decimalToBinUnsign( strValue.toStdString().c_str(), pBin );
    }
    else
    {
        QString strNum;

        if( strValue.length() % 2 )
        {
            strNum = "0";
            strNum += strValue;
        }
        else
        {
            strNum = strValue;
        }

        JS_BIN_decodeHex( strNum.toStdString().c_str(), pBin );
    }
}

void BNCalcDlg::clickBinary()
{
    mAText->setPlaceholderText( tr("valid characters: %1").arg( kBinaryChars ));
    mBText->setPlaceholderText( tr("valid characters: %1").arg( kBinaryChars ));
    mModText->setPlaceholderText( tr("valid characters: %1").arg( kBinaryChars ));
}

void BNCalcDlg::clickDecimal()
{
    mAText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
    mBText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
    mModText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
}

void BNCalcDlg::clickHex()
{
    mAText->setPlaceholderText( tr("valid characters: %1").arg( kHexChars ));
    mBText->setPlaceholderText( tr("valid characters: %1").arg( kHexChars ));
    mModText->setPlaceholderText( tr("valid characters: %1").arg( kHexChars ));
}

void BNCalcDlg::changeBaseGroup( int index )
{
    QString strName = mBaseGroupCombo->currentText();
    bool bModGroup = false;
    bool bSQRT = false;
    bool bSHL = false;
    bool bGCD = false;
    bool bMOD = false;
    bool bDIV = false;
    bool bINV = false;

    bool bAND = false;
    bool bOR = false;
    bool bXOR = false;
    bool bCOMP = false;
    bool bSHR = false;

    bool bSendM = false;

    if( strName == kNumber )
    {
        bModGroup = false;
        bSQRT = false;
        bSHL = true;
        bGCD = true;
        bMOD = true;
        bDIV = true;
        bINV = false;

        bAND = true;
        bOR = true;
        bXOR = true;
        bCOMP = true;
        bSHR = true;

        bSendM = false;

        mADDBtn->setText( kAdd );
        mSUBBtn->setText( kSub );
        mMULBtn->setText( kMul );
        mDIVBtn->setText( kDiv );
        mEXPBtn->setText( kExp );
        mSQRBtn->setText( kSqr );
        mMODBtn->setText( kMod );
        mGCDBtn->setText( kGcd );
        mORBtn->setText( kOr );
        mANDBtn->setText( kAnd );
        mXORBtn->setText( kXor );
        mCOMPBtn->setText( kComp );
        mSHLBtn->setText( kShl );
        mSHRBtn->setText( kShr );
        mINVBtn->setText( kInv );
        mSQRTBtn->setText( kSqrt );
    }
    else if( strName == kModular )
    {
        bModGroup = true;
        bSQRT = true;
        bSHL = true;
        bGCD = false;
        bMOD = false;
        bDIV = false;
        bINV = true;

        bAND = false;
        bOR = false;
        bXOR = false;
        bCOMP = false;
        bSHR = false;

        bSendM = true;

        mADDBtn->setText( kAddMod );
        mSUBBtn->setText( kSubMod );
        mMULBtn->setText( kMulMod );
        mDIVBtn->setText( kDivMod );
        mEXPBtn->setText( kExpMod );
        mSQRBtn->setText( kSqrMod );
        mSHLBtn->setText( kShlMod );
        mINVBtn->setText( kInvMod );
        mSQRTBtn->setText( kSqrtMod );
    }
    else
    {
        bModGroup = true;
        bSQRT = true;
        bSHL = false;
        bGCD = false;
        bMOD = true;
        bDIV = true;
        bINV = true;

        bAND = false;
        bOR = false;
        bXOR = false;
        bCOMP = false;
        bSHR = false;

        bSendM = true;

        mADDBtn->setText( kAdd );
        mSUBBtn->setText( kSub );
        mMULBtn->setText( kMulMod );
        mDIVBtn->setText( kDivMod );
        mEXPBtn->setText( kExpMod );
        mSQRBtn->setText( kSqrMod );
        mSHLBtn->setText( kShl );
        mINVBtn->setText( kInvMod );
        mSQRTBtn->setText( kSqrtMod );
    }

    mModGroup->setEnabled( bModGroup );
    mSQRTBtn->setEnabled( bSQRT );
    mSHLBtn->setEnabled( bSHL );
    mGCDBtn->setEnabled( bGCD );
    mMODBtn->setEnabled( bMOD );
    mDIVBtn->setEnabled( bDIV );
    mINVBtn->setEnabled( bINV );

    mANDBtn->setEnabled( bAND );
    mORBtn->setEnabled( bOR );
    mXORBtn->setEnabled( bXOR );
    mCOMPBtn->setEnabled( bCOMP );
    mSHRBtn->setEnabled( bSHR );

    mResSendModBtn->setEnabled( bSendM );
}

void BNCalcDlg::clickAGenPrime()
{
    int ret = 0;
    BIN binPrime = {0,0};
    int nBits = mAPrimeBitsCombo->currentText().toInt();

    qint64 us = 0;
    QElapsedTimer timer;

    timer.start();
    ret = JS_BN_genPrime( nBits, &binPrime );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "GenPrime fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mAText->setPlainText( getOutput( &binPrime ));
    setResTime( "A GenPrime", us );
    berApplet->log( QString( "Gen Prime Timer : %1 ms" ).arg( getMS( us ) ));

end:
    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickBGenPrime()
{
    int ret = 0;
    BIN binPrime = {0,0};
    int nBits = mBPrimeBitsCombo->currentText().toInt();

    qint64 us = 0;
    QElapsedTimer timer;

    timer.start();
    ret = JS_BN_genPrime( nBits, &binPrime );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "GenPrime: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mBText->setPlainText( getOutput( &binPrime ));
    setResTime( "B GenPrime", us );;
    berApplet->log( QString( "Gen Prime Timer : %1 ms" ).arg( getMS( us ) ));

end:
    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickModGenPrime()
{
    int ret = 0;
    BIN binPrime = {0,0};
    int nBits = mModPrimeBitsCombo->currentText().toInt();

    qint64 us = 0;
    QElapsedTimer timer;

    timer.start();
    ret = JS_BN_genPrime( nBits, &binPrime );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "GenPrime: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mModText->setPlainText( getOutput( &binPrime ));
    setResTime( "M GenPrime", us );
    berApplet->log( QString( "Gen Prime Timer : %1 ms" ).arg( getMS( us ) ));

end:
    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickAIsPrime()
{
    int ret = 0;
    BIN binVal = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString strVal = mAText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert A value" ), this );
        return;
    }

    getBIN( strVal, &binVal );
    if( binVal.nLen < 1 )
    {
        berApplet->warnLog( tr( "Invalid A value ( valid characters: %1 )" ).arg(validChars()), this );
        JS_BIN_reset( &binVal );
        return;
    }

    timer.start();
    ret = JS_BN_isPrime( &binVal );
    us = timer.nsecsElapsed() / 1000;
    setResTime( "A IsPrime", us );

    if( ret == 1 )
        berApplet->messageLog( tr( "The A value is prime"), this );
    else
        berApplet->warnLog( tr( "The A value is not prime" ), this );


    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickBIsPrime()
{
    int ret = 0;
    BIN binVal = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString strVal = mBText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert B value" ), this );
        return;
    }

    getBIN( strVal, &binVal );
    if( binVal.nLen < 1 )
    {
        berApplet->warnLog( tr( "Invalid B value ( valid characters: %1 )" ).arg(validChars()), this );
        JS_BIN_reset( &binVal );
        return;
    }

    timer.start();
    ret = JS_BN_isPrime( &binVal );
    us = timer.nsecsElapsed() / 1000;
    setResTime( "B IsPrime", us );

    if( ret == 1 )
        berApplet->messageLog( tr( "The B value is prime"), this );
    else
        berApplet->warnLog( tr( "The B value is not prime" ), this );

    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickModIsPrime()
{
    int ret = 0;
    BIN binVal = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString strVal = mModText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert M value ( valid characters: %1 )" ).arg(validChars()), this );
        return;
    }

    getBIN( strVal, &binVal );
    if( binVal.nLen < 1 )
    {
        berApplet->warnLog( tr( "Invalid M value" ), this );
        JS_BIN_reset( &binVal );
        return;
    }

    timer.start();
    ret = JS_BN_isPrime( &binVal );
    us = timer.nsecsElapsed() / 1000;
    setResTime( "M IsPrime", us );

    if( ret == 1 )
        berApplet->messageLog( tr( "The M value is prime"), this );
    else
        berApplet->warnLog( tr( "The M value is not prime" ), this );

    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickAdd()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};
    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;
        timer.start();
        ret = JS_BN_add( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;
        timer.start();
        ret = JS_BN_addMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;
        timer.start();
        ret = JS_BN_GF2m_add( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mADDBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mADDBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickSub()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString strOut;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        if( JS_BN_cmp( &binA, &binB ) < 0 )
        {
            strOut = "-";
            timer.start();
            ret = JS_BN_sub( &binR, &binB, &binA );
            us = timer.nsecsElapsed() / 1000;
        }
        else
        {
            timer.start();
            ret = JS_BN_sub( &binR, &binA, &binB );
            us = timer.nsecsElapsed() / 1000;
        }
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_subMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_sub( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    JS_BIN_rmFrontZero( &binR );
    strOut += QString( "%1" ).arg( getOutput(&binR));

    mResText->setPlainText( strOut );
    setResTime( mSUBBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mSUBBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickMultiple()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_mul( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_mulMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_mulMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mMULBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mMULBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickDiv()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binREM = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_div( &binR, &binREM, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        berApplet->elog( "Modular does not support div" );
        goto end;
    }
    else
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_divMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mDIVBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mDIVBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( binREM.nLen > 0 )
        {
            mResText->appendPlainText( QString( "REM : %1").arg( getHexString( &binREM )));
            berApplet->log( QString( "REM : %1").arg( getHexString(&binREM)));
        }
    }

    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binREM );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickExp()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_exp( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_expMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, &binB, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_expMod( &binR, &binA, &binB, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mEXPBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mEXPBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickSqr()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, NULL, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_sqr( &binR, &binA );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_sqrMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_sqrMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mSQRBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mSQRBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickMod()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_mod( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        berApplet->elog( "Modular does not support mod" );
        goto end;
    }
    else
    {
        if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_mod( &binR, &binA, &binB );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mMODBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mMODBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));

    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}


void BNCalcDlg::clickGcd()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() != kNumber )
    {
        berApplet->elog( "GCD support Number only" );
        goto end;
    }

    if( getInput( &binA, &binB, NULL ) != 0 ) goto end;

    timer.start();
    ret = JS_BN_gcd( &binR, &binA, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mGCDBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mGCDBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickOr()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_or( &binR, &binA, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mORBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mORBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickAnd()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_and( &binR, &binA, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mANDBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mANDBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickXor()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_xor( &binR, &binA, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mXORBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mXORBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "B     : %1").arg( getHexString(&binB)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickComp()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_comp( &binR, &binA );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mCOMPBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mCOMPBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));;
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShr()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;
/*
    if( mBaseGroupCombo->currentText() != kNumber )
    {
        berApplet->elog( "SHR support Number only" );
        goto end;
    }
*/
    timer.start();
    ret = JS_BN_rshift( &binR, &binA );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mSHRBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mSHRBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShl()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        if( getInput( &binA, NULL, NULL ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_lshift( &binR, &binA );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_lshiftMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        berApplet->elog( "GF2m does not support SHL" );
        goto end;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mSHLBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mSHLBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickInv()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        berApplet->elog( "Number does not support INV" );
        goto end;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_invMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_invMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mINVBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mINVBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickSqrt()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( mBaseGroupCombo->currentText() == kNumber )
    {
        berApplet->elog( "Number does not support SQRT" );
        goto end;
    }
    else if( mBaseGroupCombo->currentText() == kModular )
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_sqrtMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        if( getInput( &binA, NULL, &binMod ) != 0 ) goto end;

        timer.start();
        ret = JS_BN_GF2m_sqrtMod( &binR, &binA, &binMod );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        clearTime();
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
    setResTime( mSQRTBtn->text(), us );

    berApplet->logLine();
    berApplet->log( QString( mSQRTBtn->text() ));
    berApplet->logLine2();
    berApplet->log( QString( "A     : %1").arg( getHexString(&binA)));
    if( mBaseGroupCombo->currentText() != kNumber )
        berApplet->log( QString( "M     : %1").arg( getHexString(&binMod)));
    berApplet->log( QString( "R     : %1").arg( getHexString(&binR)));
    berApplet->log( QString( "Timer : %1 ms" ).arg( getMS( us ) ));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clearA()
{
    mAText->clear();
}

void BNCalcDlg::clearB()
{
    mBText->clear();
}

void BNCalcDlg::clearMod()
{
    mModText->clear();
}

void BNCalcDlg::clearRes()
{
    mResText->clear();
}

void BNCalcDlg::clearAll()
{
    clearA();
    clearB();
    clearMod();
    clearRes();
    clearTime();
    clearSum();
}

void BNCalcDlg::addOneA()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_add1( &binR, &binA );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mAText->setPlainText( getOutput( &binR ) );
    setResTime( "A+1", us );

    berApplet->logLine();
    berApplet->log( QString( "A+1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::addOneB()
{
    int ret = 0;
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( NULL, &binB, NULL ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_add1( &binR, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mBText->setPlainText( getOutput( &binR ) );
    setResTime( "B+1", us );

    berApplet->logLine();
    berApplet->log( QString( "B+1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::addOneMod()
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( NULL, NULL, &binMod ) != 0 )
        goto end;

    timer.start();
    ret = JS_BN_add1( &binR, &binMod );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mModText->setPlainText( getOutput( &binR ) );
    setResTime( "M+1", us );

    berApplet->logLine();
    berApplet->log( QString( "M+1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::subOneA()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;

    if( binA.nLen == 0 || (binA.nLen == 1 && binA.pVal[0] == 0x00) )
    {
        berApplet->warnLog( QString( tr( "Number must be greater than 0") ), this);
        goto end;
    }

    timer.start();
    ret = JS_BN_sub1( &binR, &binA );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mAText->setPlainText( getOutput( &binR ) );
    setResTime( "A-1", us );

    berApplet->logLine();
    berApplet->log( QString( "A-1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::subOneB()
{
    int ret = 0;
    BIN binB = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( NULL, &binB, NULL ) != 0 )
        goto end;

    if( binB.nLen == 0 || (binB.nLen == 1 && binB.pVal[0] == 0x00) )
    {
        berApplet->warnLog( QString( tr( "Number must be greater than 0") ), this);
        goto end;
    }

    timer.start();
    ret = JS_BN_sub1( &binR, &binB );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mBText->setPlainText( getOutput( &binR ) );
    setResTime( "B-1", us );

    berApplet->logLine();
    berApplet->log( QString( "B-1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::subOneMod()
{
    int ret = 0;
    BIN binMod = {0,0};
    BIN binR = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    if( getInput( NULL, NULL, &binMod ) != 0 )
        goto end;

    if( binMod.nLen == 0 || (binMod.nLen == 1 && binMod.pVal[0] == 0x00) )
    {
        berApplet->warnLog( QString( tr( "Number must be greater than 0") ), this);
        goto end;
    }

    timer.start();
    ret = JS_BN_sub1( &binR, &binMod );
    us = timer.nsecsElapsed() / 1000;

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mModText->setPlainText( getOutput( &binR ) );
    setResTime( "M-1", us );

    berApplet->logLine();
    berApplet->log( QString( "M-1 : %1").arg( getHexString(&binR)));
    berApplet->logLine();

end :
    JS_BIN_reset( &binMod );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::changeA()
{
    int nLen = mAText->toPlainText().length();
    mALenText->setText( QString("%1").arg( nLen ));
}

void BNCalcDlg::changeB()
{
    int nLen = mBText->toPlainText().length();
    mBLenText->setText( QString("%1").arg( nLen ));
}

void BNCalcDlg::changeMod()
{
    int nLen = mModText->toPlainText().length();
    mModLenText->setText( QString("%1").arg( nLen ));
}

void BNCalcDlg::changeRes()
{
    int nLen = mResText->toPlainText().length();
    mResLenText->setText( QString("%1").arg( nLen ));
}

void BNCalcDlg::clickACopy()
{
    QString strMsg = mAText->toPlainText().simplified();
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( strMsg );
}

void BNCalcDlg::clickAPaste()
{
    QClipboard *clipboard = QGuiApplication::clipboard();
    QString strMsg = clipboard->text();
    mAText->setPlainText( strMsg );
}

void BNCalcDlg::clickBCopy()
{
    QString strMsg = mBText->toPlainText().simplified();
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( strMsg );
}

void BNCalcDlg::clickBPaste()
{
    QClipboard *clipboard = QGuiApplication::clipboard();
    QString strMsg = clipboard->text();
    mBText->setPlainText( strMsg );
}

void BNCalcDlg::clickModCopy()
{
    QString strMsg = mModText->toPlainText().simplified();
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( strMsg );
}

void BNCalcDlg::clickModPaste()
{
    QClipboard *clipboard = QGuiApplication::clipboard();
    QString strMsg = clipboard->text();
    mModText->setPlainText( strMsg );
}

void BNCalcDlg::clickResCopy()
{
    QString strMsg = mResText->toPlainText().simplified();
    QClipboard *clipboard = QGuiApplication::clipboard();
    clipboard->setText( strMsg );
}

void BNCalcDlg::clickResSendA()
{
    QString strRes = mResText->toPlainText().simplified();

    mAText->setPlainText( strRes );
}

void BNCalcDlg::clickResSendB()
{
    QString strRes = mResText->toPlainText().simplified();

    mBText->setPlainText( strRes );
}

void BNCalcDlg::clickResSendMod()
{
    QString strRes = mResText->toPlainText().simplified();

    mModText->setPlainText( strRes );
}

void BNCalcDlg::clickTest()
{
    int ret = -1;
    char *pHex = NULL;

    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binMod = {0,0};
    BIN binR = {0,0};

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    BIGNUM* m = BN_new();
    BIGNUM* r = BN_new();

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    BN_bin2bn( binA.pVal, binA.nLen, a );
    BN_bin2bn( binB.pVal, binB.nLen, b );
    BN_bin2bn( binMod.pVal, binMod.nLen, m );

    berApplet->log( QString( "A: %1" ).arg( BN_bn2hex(a)));
    berApplet->log( QString( "B: %1" ).arg( BN_bn2hex(b)));
    berApplet->log( QString( "Mod: %1").arg( BN_bn2hex(m)));

    ret = BN_GF2m_mod_div( r, a, b, m, ctx );

    if( ret == 1 )
    {
        pHex = BN_bn2hex( r );
        JS_BIN_decodeHex( pHex, &binR );
        ret = 0;
    }
    else
    {
        unsigned long uerr = ERR_get_error();
        berApplet->log( QString("BN Error(%1:%2)").arg( uerr ).arg( ERR_error_string( uerr, NULL )) );
        ret = -1;
    }

    mResText->setPlainText( getHexString( &binR ));

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clearTime()
{
    mResTimeText->clear();
    mCalcLabel->setText( tr("Calculation" ));

    time_us_ = 0;
}

void BNCalcDlg::clearSum()
{
    mSumTimeText->clear();
    sum_us_ = 0;
}

void BNCalcDlg::clickAddSum()
{
    sum_us_ += time_us_;
    mSumTimeText->setText( QString( "%1" ).arg( getMS( sum_us_ )));
}

void BNCalcDlg::clickSubSum()
{
    sum_us_ -= time_us_;
    if( sum_us_ < 0 ) sum_us_ = 0;
    mSumTimeText->setText( QString( "%1" ).arg( getMS( sum_us_ )));
}

void BNCalcDlg::setResTime( const QString strCmd, qint64 time_us )
{
    time_us_ = time_us;
    mCalcLabel->setText( strCmd );
    mResTimeText->setText( QString( "%1" ).arg( getMS(time_us)));

    if( mAutoSumCheck->isChecked() ) clickAddSum();
}
