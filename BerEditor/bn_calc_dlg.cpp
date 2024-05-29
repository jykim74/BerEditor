#include "common.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "bn_calc_dlg.h"
#include "js_bn.h"
#include "ber_applet.h"

#include <QRegExpValidator>

const QStringList kBitType = { "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "3072", "4096" };
const QStringList kGroupList = { "Number", "Modular", "GF2m" };

BNCalcDlg::BNCalcDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mBinCheck, SIGNAL(clicked()), this, SLOT(clickBinary()));
    connect( mDecCheck, SIGNAL(clicked()), this, SLOT(clickDecimal()));
    connect( mHexCheck, SIGNAL(clicked()), this, SLOT(clickHex()));

    connect( mAGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickAGenPrime()));
    connect( mBGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickBGenPrime()));
    connect( mModGenPrimeBtn, SIGNAL(clicked()), this, SLOT(clickModGenPrime()));

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mSubBtn, SIGNAL(clicked()), this, SLOT(clickSub()));
    connect( mMultipleBtn, SIGNAL(clicked()), this, SLOT(clickMultiple()));
    connect( mDivBtn, SIGNAL(clicked()), this, SLOT(clickDiv()));
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

    connect( mAClearBtn, SIGNAL(clicked()), this, SLOT(clearA()));
    connect( mBClearBtn, SIGNAL(clicked()), this, SLOT(clearB()));
    connect( mModClearBtn, SIGNAL(clicked()), this, SLOT(clearMod()));
    connect( mResClearBtn, SIGNAL(clicked()), this, SLOT(clearRes()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clearAll()));

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

    mAPrimeBitsCombo->addItems(kBitType);
    mBPrimeBitsCombo->addItems(kBitType);
    mModPrimeBitsCombo->addItems( kBitType );

    mAPrimeBitsCombo->setEditable(true);
    mBPrimeBitsCombo->setEditable(true);
}

int BNCalcDlg::getInput( BIN *pA, BIN *pB, BIN *pMod )
{
    int nNum = 0;

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    if( mBinCheck->isChecked() )
    {
        nNum = 2;
        JS_PKI_bitToBin( strA.toStdString().c_str(), pA );
        JS_PKI_bitToBin( strB.toStdString().c_str(), pB );
        JS_PKI_bitToBin( strMod.toStdString().c_str(), pMod );
    }
    else if( mDecCheck->isCheckable() )
    {
        nNum = 10;
        JS_PKI_decimalToBin( strA.toStdString().c_str(), pA );
        JS_PKI_decimalToBin( strB.toStdString().c_str(), pB );
        JS_PKI_decimalToBin( strMod.toStdString().c_str(), pMod );
    }
    else
    {
        nNum = 16;
        JS_BIN_decodeHex( strA.toStdString().c_str(), pA );
        JS_BIN_decodeHex( strB.toStdString().c_str(), pB );
        JS_BIN_decodeHex( strMod.toStdString().c_str(), pMod );
    }

    if( isValidNumFormat( strA, nNum ) != 1 )
        return -1;

    if( isValidNumFormat( strB, nNum ) != 1 )
        return -2;

    if( isValidNumFormat( strMod, nNum ) != 1 )
        return -3;

    return 0;
}

const QString BNCalcDlg::getOutput( const BIN *pBin )
{
    QString strValue;

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
        JS_PKI_binToDecimal( pBin, &pString );
        strValue = pString;
        if( pString ) JS_free( pString );
    }
    else
    {
        strValue = getHexString( pBin );
    }

    return strValue;
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

void BNCalcDlg::clickAGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mAPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mAText->setPlainText( getHexString( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickBGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mBPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mBText->setPlainText( getHexString( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickModGenPrime()
{
    BIN binPrime = {0,0};
    int nBits = mModPrimeBitsCombo->currentText().toInt();

    JS_BN_genPrime( nBits, &binPrime );
    mModText->setPlainText( getHexString( &binPrime ));

    JS_BIN_reset( &binPrime );
}

void BNCalcDlg::clickAdd()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_add( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_addMod( &binR, &binA, &binB, &binMod );
    else
        JS_BN_GF2m_add( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickSub()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    QString strOut;

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
    {
        if( JS_BN_cmp( &binA, &binB ) < 0 )
            strOut = "-";

        JS_BN_sub( &binR, &binA, &binB );
    }
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_subMod( &binR, &binA, &binB, &binMod );
    else
        JS_BN_GF2m_sub( &binR, &binA, &binB );

    JS_BIN_rmFrontZero( &binR );

    strOut += QString( "%1" ).arg( getHexString(&binR));

    mResText->setPlainText( strOut );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickMultiple()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_mul( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_mulMod( &binR, &binA, &binB, &binMod );
    else
        JS_BN_GF2m_mulMod( &binR, &binA, &binB, &binMod );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickDiv()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binREM = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_div( &binR, &binREM, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
    {
        berApplet->elog( "Modular does not support div" );
        goto end;
    }
    else
        JS_BN_GF2m_mulMod( &binR, &binA, &binB, &binMod );

    mResText->setPlainText( getHexString( &binR ) );

    if( mBaseGroupCombo->currentText() == "Number" )
        mResText->appendPlainText( QString( "\n\nREM : %1").arg( getHexString( &binREM )));

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binREM );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickExp()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_exp( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_expMod( &binR, &binA, &binB, &binMod );
    else
        JS_BN_GF2m_expMod( &binR, &binA, &binB, &binMod );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickSqr()
{
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_sqr( &binR, &binA );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_sqrMod( &binR, &binA, &binMod );
    else
        JS_BN_GF2m_sqrMod( &binR, &binA, &binMod );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickMod()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    JS_BN_mod( &binR, &binA, &binB );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_mod( &binR, &binA, &binB );
    else if( mBaseGroupCombo->currentText() == "Modular" )
    {
        berApplet->elog( "Modular does not support mod" );
        goto end;
    }
    else
        JS_BN_GF2m_mod( &binR, &binA, &binMod );

    mResText->setPlainText( getHexString( &binR ) );
end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}


void BNCalcDlg::clickGcd()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    if( mBaseGroupCombo->currentText() != "Number" )
    {
        berApplet->elog( "GCM support Number only" );
        goto end;
    }

    JS_BN_gcd( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );
end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickOr()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_or( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickAnd()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_and( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickXor()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_xor( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickComp()
{
    BIN binA = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );

    JS_BN_comp( &binR, &binA );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShr()
{
    BIN binA = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
/*
    if( mBaseGroupCombo->currentText() != "Number" )
    {
        berApplet->elog( "SHR support Number only" );
        goto end;
    }
*/
    JS_BN_rshift( &binR, &binA );
    mResText->setPlainText( getHexString( &binR ) );

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShl()
{
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_lshift( &binR, &binA );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_lshiftMod( &binR, &binA, &binMod );
    else
    {
        berApplet->elog( "GF2m does not support SHL" );
        goto end;
    }

    mResText->setPlainText( getHexString( &binR ) );

end :
    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binMod );
}

void BNCalcDlg::clickInv()
{
    BIN binA = {0,0};
    BIN binR = {0,0};
    BIN binMod = {0,0};

    QString strA = mAText->toPlainText();
    QString strMod = mModText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strMod.toStdString().c_str(), &binMod );

    if( mBaseGroupCombo->currentText() == "Number" )
        JS_BN_inv( &binR, &binA );
    else if( mBaseGroupCombo->currentText() == "Modular" )
        JS_BN_invMod( &binR, &binA, &binMod );
    else
        Js_BN_GF2m_invMod( &binR, &binA, &binMod );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
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
