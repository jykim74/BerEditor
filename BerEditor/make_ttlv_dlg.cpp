#include <QStringList>
#include "make_ttlv_dlg.h"
#include "js_kms.h"
#include "common.h"
#include "ber_applet.h"
#include "mainwindow.h"

const QStringList kTTLVTypeList = { "None", "Structure", "Integer", "LongInteger",
                                   "BigInteger", "Enumeration", "Boolean", "TextString",
                                    "ByteString", "DateTime", "Interval", "DateTimeExtented" };

MakeTTLVDlg::MakeTTLVDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mTagText, SIGNAL(textChanged(QString)), this, SLOT(changeTag(QString)));
    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType(int)));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));
    connect( mTTLVText, SIGNAL(textChanged()), this, SLOT(changeTTLV()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

    initialize();

    mCancelBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

MakeTTLVDlg::~MakeTTLVDlg()
{

}

void MakeTTLVDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void MakeTTLVDlg::initialize()
{
    QRegExp regExp("^[0-9a-fA-F]*$");
    QRegExpValidator* regVal = new QRegExpValidator( regExp );

    mTagText->setValidator( regVal );
    mTypeCombo->addItems( kTTLVTypeList );
    mTypeCombo->setCurrentIndex(1);
    mValueCombo->addItems( kValueTypeList );
    mValueCombo->setCurrentIndex(1);
}

void MakeTTLVDlg::changeType( int index )
{
    mTypeText->setText( QString("%1").arg( index, 2, 16, QLatin1Char('0')).toUpper());
    makeHeader();
}

void MakeTTLVDlg::changeTag( const QString text )
{
    if( text.length() < 6 )
    {
        mTagNameText->clear();
        return;
    }

    int nTag = text.toInt(nullptr, 16);
    QString strName = JS_KMS_tagName( nTag );
    mTagNameText->setText( strName );

    makeHeader();
}

void MakeTTLVDlg::changeValue()
{
    QString strValue = mValueText->toPlainText();

    int nLen = getDataLen( mValueCombo->currentText(), strValue );

    mValueLenText->setText( QString("%1").arg( nLen ));
    mLengthText->setText( QString( "%1").arg( nLen, 8, 16, QLatin1Char('0') ).toUpper());

    makeHeader();
}

void MakeTTLVDlg::changeTTLV()
{
    QString strTTLV = mTTLVText->toPlainText();
    int nLen = getDataLen( DATA_HEX, strTTLV );
    mTTLVLenText->setText( QString("%1").arg( nLen ));
}

void MakeTTLVDlg::makeHeader()
{
    QString strTag = mTagText->text();
    QString strValue = mValueText->toPlainText();

    if( strTag.length() < 6 ) return;

    int nLen = getDataLen( mValueCombo->currentText(), strValue );


    QString strHeader = QString( "%1%2%3" )
                            .arg( strTag )
                            .arg( mTypeCombo->currentIndex(), 2, 16, QLatin1Char('0') )
                            .arg( nLen, 8, 16, QLatin1Char('0') );

    mHeaderText->setText( strHeader.toUpper() );
    mTTLVText->setPlainText( getData() );
}

QString MakeTTLVDlg::getData()
{
    QString strData;
    QString strValue = mValueText->toPlainText();
    BIN binData = {0,0};

    getBINFromString( &binData, mValueCombo->currentText(), strValue );

    int nAppend = 8 - binData.nLen % 8;
    if( nAppend > 0 && nAppend != 8 ) JS_BIN_appendCh( &binData, 0x00, nAppend );

    strData = mHeaderText->text();
    strData += getHexString( &binData );

    JS_BIN_reset( &binData );

    return strData.toUpper();
}

void MakeTTLVDlg::clickOK()
{
    QString strData = getData();

    if( strData.length() > 8 )
    {
        accept();
    }
    else
    {
        reject();
        return;
    }
}
