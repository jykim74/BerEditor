#include "ber_define.h"
#include "data_encoder_dlg.h"
#include "js_bin.h"
#include "js_util.h"

static const char* entypes[] = {
    "string",
    "hex",
    "base64",
    "URL"
};

DataEncoderDlg::DataEncoderDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    QStringList typeList;

    for( int i=0; i < (sizeof(entypes) / sizeof(entypes[0])); i++ )
        typeList.push_back( entypes[i] );

    mOutputTypeCombo->addItems(typeList);

    connect( mEncodeBtn, SIGNAL(clicked()), this, SLOT(onClickEncodeBtn()));
}

DataEncoderDlg::~DataEncoderDlg()
{

}

void DataEncoderDlg::onClickEncodeBtn()
{
    int input_type = 0;
    int output_type = 0;
    BIN binSrc = {0,0};
    char *pOut = NULL;

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
        mOutputTextEdit->setPlainText( mInputTextEdit->toPlainText() );
    else {
        QString inputStr = mInputTextEdit->toPlainText();

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
            JS_BIN_string( &binSrc, &pOut );
            mOutputTextEdit->setPlainText( pOut );
        }
        else if( output_type == DATA_HEX )
        {
            JS_BIN_encodeHex( &binSrc, &pOut);
            mOutputTextEdit->setPlainText(pOut);
        }
        else if( output_type == DATA_BASE64 )
        {
            JS_BIN_encodeBase64( &binSrc, &pOut );
            mOutputTextEdit->setPlainText(pOut);
        }
        else if( output_type == DATA_URL )
        {
            char *pStr = NULL;
            JS_BIN_string( &binSrc, &pStr );
            JS_UTIL_encodeURL( pStr, &pOut );
            mOutputTextEdit->setPlainText(pOut);
            if( pStr ) JS_free(pStr);
        }
    }

    JS_BIN_reset(&binSrc);
    if( pOut ) JS_free( pOut );
}
