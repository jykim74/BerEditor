#include "common.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "bn_calc_dlg.h"

#include <QRegExpValidator>

BNCalcDlg::BNCalcDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mBinCheck, SIGNAL(clicked()), this, SLOT(clickBinary()));
    connect( mDecCheck, SIGNAL(clicked()), this, SLOT(clickDecimal()));
    connect( mHexCheck, SIGNAL(clicked()), this, SLOT(clickHex()));

    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mSubBtn, SIGNAL(clicked()), this, SLOT(clickSub()));
    connect( mMultipleBtn, SIGNAL(clicked()), this, SLOT(clickMultiple()));
    connect( mDivBtn, SIGNAL(clicked()), this, SLOT(clickDiv()));

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

void BNCalcDlg::clickAdd()
{

}

void BNCalcDlg::clickSub()
{

}

void BNCalcDlg::clickMultiple()
{

}

void BNCalcDlg::clickDiv()
{

}
