#include "common.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "bn_calc_dlg.h"
#include "js_bn.h"

#include <QRegExpValidator>

const QStringList kBitType = { "8", "16", "32", "64", "128", "256", "512", "1024", "2048", "3072", "4096" };
const QStringList kGroupList = { "Number", "Modulus", "GF2m" };

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
    mDecCheck->click();

    mBaseGroupCombo->addItems( kGroupList );

    mAPrimeBitsCombo->addItems(kBitType);
    mBPrimeBitsCombo->addItems(kBitType);
    mModPrimeBitsCombo->addItems( kBitType );

    mAPrimeBitsCombo->setEditable(true);
    mBPrimeBitsCombo->setEditable(true);
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

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_add( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickSub()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_sub( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickMultiple()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_mul( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickDiv()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};
    BIN binREM = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_div( &binR, &binREM, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );
    mResText->appendPlainText( QString( "\n\nREM : %1").arg( getHexString( &binREM )));

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
    JS_BIN_reset( &binREM );
}

void BNCalcDlg::clickExp()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_exp( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickSqr()
{
    BIN binA = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );

    JS_BN_sqr( &binR, &binA );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickMod()
{
    BIN binA = {0,0};
    BIN binB = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();
    QString strB = mBText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );
    JS_BIN_decodeHex( strB.toStdString().c_str(), &binB );

    JS_BN_mod( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binB );
    JS_BIN_reset( &binR );
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

    JS_BN_gcd( &binR, &binA, &binB );

    mResText->setPlainText( getHexString( &binR ) );

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

    JS_BN_rshift( &binR, &binA );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickShl()
{
    BIN binA = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );

    JS_BN_lshift( &binR, &binA );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}

void BNCalcDlg::clickInv()
{
    BIN binA = {0,0};
    BIN binR = {0,0};

    QString strA = mAText->toPlainText();

    JS_BIN_decodeHex( strA.toStdString().c_str(), &binA );

    JS_BN_inv( &binR, &binA );

    mResText->setPlainText( getHexString( &binR ) );

    JS_BIN_reset( &binA );
    JS_BIN_reset( &binR );
}
