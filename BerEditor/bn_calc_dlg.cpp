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

const QStringList kBitType = { "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "3072", "4096" };
const QStringList kGroupList = { "Number", "Modular", "GF2m" };

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

    connect( mACheckPrimeBtn, SIGNAL(clicked()), this, SLOT(clickACheckPrime()));
    connect( mBCheckPrimeBtn, SIGNAL(clicked()), this, SLOT(clickBCheckPrime()));
    connect( mModCheckPrimeBtn, SIGNAL(clicked()), this, SLOT(clickModCheckPrime()));

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mSubBtn, SIGNAL(clicked()), this, SLOT(clickSub()));
    connect( mMultipleBtn, SIGNAL(clicked()), this, SLOT(clickMultiple()));
    connect( mDIVBtn, SIGNAL(clicked()), this, SLOT(clickDiv()));
    connect( mSqrBtn, SIGNAL(clicked()), this, SLOT(clickSqr()));
    connect( mExpBtn, SIGNAL(clicked()), this, SLOT(clickExp()));

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


    connect( mTestBtn, SIGNAL(clicked()), this, SLOT(clickTest()));

    intialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

BNCalcDlg::~BNCalcDlg()
{

}

void BNCalcDlg::intialize()
{
    mHexCheck->click();

    mBaseGroupCombo->addItems( kGroupList );
    mBaseGroupCombo->setCurrentIndex(1);

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
}


int BNCalcDlg::getInput( BIN *pA, BIN *pB, BIN *pMod )
{
    int nNum = 0;

    QString strA = mAText->toPlainText().simplified();
    QString strB = mBText->toPlainText().simplified();
    QString strMod = mModText->toPlainText().simplified();

    if( mBaseGroupCombo->currentText() == "Number" )
        strMod.clear();

    if( mBinCheck->isChecked() )
        nNum = 2;
    else if( mDecCheck->isChecked() )
        nNum = 10;
    else
        nNum = 16;

    if( pA != NULL && strA.length() > 0 )
    {
        if( isValidNumFormat( strA, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The A value have wrong character" ), this );
            return -1;
        }

        getBIN( strA, pA );
    }

    if( pB != NULL && strB.length() > 0 )
    {
        if( isValidNumFormat( strB, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The B value have wrong character" ), this );
            return -2;
        }

        getBIN( strB, pB );
    }

    if( pMod != NULL && strMod.length() > 0 )
    {
        if( isValidNumFormat( strMod, nNum ) != 1 )
        {
            berApplet->warningBox( tr( "The Mod value have wrong character" ), this );
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
        JS_BIN_decodeHex( strValue.toStdString().c_str(), pBin );
    }
}

void BNCalcDlg::clickBinary()
{
    QRegExp regExp("^[0-1]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
}

void BNCalcDlg::clickDecimal()
{
    QRegExp regExp("^[0-9]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );

}

void BNCalcDlg::clickHex()
{
    QRegExp regExp("^[0-9.]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );
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

    if( strName == "Number" )
    {
        bModGroup = false;
        bSQRT = false;
        bSHL = true;
        bGCD = true;
        bMOD = true;
        bDIV = true;
        bINV = false;
    }
    else if( strName == "Modular" )
    {
        bModGroup = true;
        bSQRT = true;
        bSHL = true;
        bGCD = false;
        bMOD = false;
        bDIV = false;
        bINV = true;
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
    }

    mModGroup->setEnabled( bModGroup );
    mSQRTBtn->setEnabled( bSQRT );
    mSHLBtn->setEnabled( bSHL );
    mGCDBtn->setEnabled( bGCD );
    mMODBtn->setEnabled( bMOD );
    mDIVBtn->setEnabled( bDIV );
    mINVBtn->setEnabled( bINV );
}

void BNCalcDlg::clickAGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mAPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mAText->setPlainText( getOutput( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickBGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mBPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mBText->setPlainText( getOutput( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickModGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mModPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mModText->setPlainText( getOutput( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickACheckPrime()
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strVal = mAText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert A value" ), this );
        return;
    }

    getBIN( strVal, &binVal );

    ret = JS_BN_isPrime( &binVal );

    if( ret == 1 )
        berApplet->messageLog( tr( "The A value is prime"), this );
    else
        berApplet->warnLog( tr( "The A value is not prime" ), this );

    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickBCheckPrime()
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strVal = mBText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert B value" ), this );
        return;
    }

    getBIN( strVal, &binVal );

    ret = JS_BN_isPrime( &binVal );

    if( ret == 1 )
        berApplet->messageLog( tr( "The B value is prime"), this );
    else
        berApplet->warnLog( tr( "The B value is not prime" ), this );

    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickModCheckPrime()
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strVal = mModText->toPlainText();

    if( strVal.length() < 1 )
    {
        berApplet->warningBox( tr( "Insert Mod value" ), this );
        return;
    }

    getBIN( strVal, &binVal );

    ret = JS_BN_isPrime( &binVal );

    if( ret == 1 )
        berApplet->messageLog( tr( "The Mod value is prime"), this );
    else
        berApplet->warnLog( tr( "The Mod value is not prime" ), this );

    JS_BIN_reset( &binVal );
}

void BNCalcDlg::clickAdd()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret =JS_BN_add( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_addMod( &binR, &binA, &binB, &binMod );
    else
        ret = JS_BN_GF2m_add( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );

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

    QString strOut;

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
    {
        if( JS_BN_cmp( &binA, &binB ) < 0 )
            strOut = "-";

        ret = JS_BN_sub( &binR, &binA, &binB );
    }
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_subMod( &binR, &binA, &binB, &binMod );
    else
        ret = JS_BN_GF2m_sub( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    JS_BIN_rmFrontZero( &binR );

    strOut += QString( "%1" ).arg( getOutput(&binR));

    mResText->setPlainText( strOut );
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

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_mul( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_mulMod( &binR, &binA, &binB, &binMod );
    else
        ret = JS_BN_GF2m_mulMod( &binR, &binA, &binB, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_div( &binR, &binREM, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
    {
        berApplet->elog( "Modular does not support div" );
        goto end;
    }
    else
        ret = JS_BN_GF2m_divMod( &binR, &binA, &binB, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );

    if( mBaseGroupCombo->currentText() == "Number" )
        mResText->appendPlainText( QString( "REM : %1").arg( getHexString( &binREM )));

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

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_exp( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_expMod( &binR, &binA, &binB, &binMod );
    else
        ret = JS_BN_GF2m_expMod( &binR, &binA, &binB, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_sqr( &binR, &binA );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_sqrMod( &binR, &binA, &binMod );
    else
        ret = JS_BN_GF2m_sqrMod( &binR, &binA, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickMod()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    if( getInput( &binA, &binB, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_mod( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
    {
        berApplet->elog( "Modular does not support mod" );
        goto end;
    }
    else
        ret = JS_BN_GF2m_mod( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}


void BNCalcDlg::clickGcd()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() != "Number" )
    {
        berApplet->elog( "GCD support Number only" );
        goto end;
    }

    ret = JS_BN_gcd( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    ret = JS_BN_or( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    ret = JS_BN_and( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, &binB, NULL ) != 0 )
        goto end;

    ret = JS_BN_xor( &binR, &binA, &binB );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;

    ret = JS_BN_comp( &binR, &binA );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShr()
{
    int ret = 0;
    BIN binA = {0,0};
    BIN binR = {0,0};

    if( getInput( &binA, NULL, NULL ) != 0 )
        goto end;
/*
    if( mBaseGroupCombo->currentText() != "Number" )
    {
        berApplet->elog( "SHR support Number only" );
        goto end;
    }
*/
    ret = JS_BN_rshift( &binR, &binA );
    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );

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

    if( getInput( &binA, NULL, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
        ret = JS_BN_lshift( &binR, &binA );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_lshiftMod( &binR, &binA, &binMod );
    else
    {
        berApplet->elog( "GF2m does not support SHL" );
        goto end;
    }

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );

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

    if( getInput( &binA, NULL, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
    {
        berApplet->elog( "Number does not support INV" );
        goto end;
    }
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_invMod( &binR, &binA, &binMod );
    else
        ret = JS_BN_GF2m_invMod( &binR, &binA, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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

    if( getInput( &binA, NULL, &binMod ) != 0 )
        goto end;

    if( mBaseGroupCombo->currentText() == "Number" )
    {
        berApplet->elog( "Number does not support SQRT" );
        goto end;
    }
    else if( mBaseGroupCombo->currentText() == "Modular" )
        ret = JS_BN_sqrtMod( &binR, &binA, &binMod );
    else
        ret = JS_BN_GF2m_sqrtMod( &binR, &binA, &binMod );

    if( ret != 0 )
    {
        berApplet->warnLog( QString( tr( "Calc fail: %1").arg( JS_BN_lastError())), this);
        goto end;
    }

    mResText->setPlainText( getOutput( &binR ) );
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
