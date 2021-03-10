#include <QStringList>

#include "num_trans_dlg.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_util.h"

const QStringList sTypeList = { "Bit", "Decimal", "Hex" };

NumTransDlg::NumTransDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

     mOutputTypeCombo->addItems( sTypeList );

     connect( mTransBtn, SIGNAL(clicked()), this, SLOT(dataTrans()));
     connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(dataChange()));
     connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

     mCloseBtn->setFocus();
}

NumTransDlg::~NumTransDlg()
{

}


void NumTransDlg::dataTrans()
{
    BIN binSrc = {0,0};
    BIN binDst = {0,0};
    char *pOutput = NULL;

    QString strInput = mInputText->toPlainText();

    if( mBitBtn->isChecked() )
        JS_PKI_bitToBin( strInput.toStdString().c_str(), &binSrc );
    else if( mDecimalBtn->isChecked() )
        JS_PKI_decimalToBin( strInput.toStdString().c_str(), &binSrc );
    else if( mHexBtn->isChecked() )
        JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );

    if( mOutputTypeCombo->currentIndex() == 0 )
        JS_PKI_binToBit( &binSrc, &pOutput );
    else if( mOutputTypeCombo->currentIndex() == 1 )
        JS_PKI_binToDecimal( &binSrc, &pOutput );
    else if( mOutputTypeCombo->currentIndex() == 2 )
        JS_BIN_encodeHex( &binSrc, &pOutput );

    if( mOutputTypeCombo->currentIndex() == 0 )
    {
        char *pTrimOut = JS_UTIL_trimChLeft( '0', pOutput );
        mOutputText->setPlainText( pTrimOut );
    }
    else
    {
        mOutputText->setPlainText( pOutput );
    }

    if( pOutput ) JS_free( pOutput );
    repaint();
}

void NumTransDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();
    mOutputText->clear();

    mInputText->setPlainText( strOutput );

    if( mOutputTypeCombo->currentIndex() == 0 )
        mBitBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mDecimalBtn->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mHexBtn->setChecked(true);

    repaint();
}
