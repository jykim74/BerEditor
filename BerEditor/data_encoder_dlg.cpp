#include "data_encoder_dlg.h"
#include "js_bin.h"
#include "js_util.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "common.h"

static QStringList enTypes = {
    "String",
    "Hex",
    "Base64",
    "URL"
};

DataEncoderDlg::DataEncoderDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mOutputTypeCombo->addItems( enTypes );

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(onClickEncodeBtn()));
    connect( mOutputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(outTypeChanged(int)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mInputTypeURL, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeHexBtn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeBase64Btn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputTypeStringBtn, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));

    mCloseBtn->setFocus();
}

DataEncoderDlg::~DataEncoderDlg()
{

}

static char getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

void DataEncoderDlg::onClickEncodeBtn()
{
    int input_type = 0;
    int output_type = 0;
    BIN binSrc = {0,0};
    char *pOut = NULL;

    QString inputStr = mInputText->toPlainText();
    if( inputStr.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert data" ), this );
        return;
    }

    if( mInputTypeStringBtn->isChecked() )
        input_type = DATA_STRING;
    else if( mInputTypeHexBtn->isChecked() )
        input_type = DATA_HEX;
    else if( mInputTypeBase64Btn->isChecked() )
        input_type = DATA_BASE64;
    else if( mInputTypeURL->isChecked() )
        input_type = DATA_URL;

    output_type = mOutputTypeCombo->currentIndex();

    if( input_type == output_type )
        mOutputText->setPlainText( mInputText->toPlainText() );
    else {

        if( input_type == DATA_STRING )
        {
            JS_BIN_set( &binSrc, (unsigned char *)inputStr.toStdString().c_str(), inputStr.length() );
        }
        else if( input_type == DATA_HEX )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( input_type == DATA_BASE64)
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( input_type == DATA_URL )
        {
            char *pStr = NULL;
            JS_UTIL_decodeURL( inputStr.toStdString().c_str(), &pStr );
            if( pStr )
            {
                JS_BIN_set( &binSrc, (unsigned char *)pStr, strlen(pStr));
                JS_free( pStr );
            }
        }

        if( output_type == DATA_STRING )
        {
            int i = 0;

            if( mShowPrintTextCheck->isChecked() )
            {
                if( binSrc.nLen > 0 )
                {
                    pOut = (char *)JS_malloc(binSrc.nLen + 1);

                    for( i=0; i < binSrc.nLen; i++ )
                        pOut[i] = getch( binSrc.pVal[i] );

                    pOut[i] = 0x00;
                }
            }
            else
            {
                JS_BIN_string( &binSrc, &pOut );
            }

            mOutputText->setPlainText( pOut );
        }
        else if( output_type == DATA_HEX )
        {
            JS_BIN_encodeHex( &binSrc, &pOut);
            mOutputText->setPlainText(pOut);
        }
        else if( output_type == DATA_BASE64 )
        {
            JS_BIN_encodeBase64( &binSrc, &pOut );
            mOutputText->setPlainText(pOut);
        }
        else if( output_type == DATA_URL )
        {
            char *pStr = NULL;
            JS_BIN_string( &binSrc, &pStr );
            JS_UTIL_encodeURL( pStr, &pOut );
            mOutputText->setPlainText(pOut);
            if( pStr ) JS_free(pStr);
        }
    }

    JS_BIN_reset(&binSrc);
    if( pOut ) JS_free( pOut );
    repaint();
}

void DataEncoderDlg::outTypeChanged(int index)
{
    if( index == 0 )
    {
        mShowPrintTextCheck->setEnabled(true);
    }
    else
    {
        mShowPrintTextCheck->setEnabled(false);
    }
}

void DataEncoderDlg::inputChanged()
{
    int nInputType = 0;

    if( mInputTypeStringBtn->isChecked() )
        nInputType = DATA_STRING;
    else if( mInputTypeHexBtn->isChecked() )
        nInputType = DATA_HEX;
    else if( mInputTypeBase64Btn->isChecked() )
        nInputType = DATA_BASE64;
    else if( mInputTypeURL->isChecked() )
        nInputType = DATA_URL;

    int nLen = getDataLen( nInputType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void DataEncoderDlg::outputChanged()
{
    int nLen = getDataLen( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}
