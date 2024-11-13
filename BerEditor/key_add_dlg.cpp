#include <QFile>
#include <QTextStream>

#include "key_add_dlg.h"
#include "ui_key_add_dlg.h"
#include "ber_applet.h"
#include "common.h"
#include "settings_mgr.h"

#include "js_pki.h"

static const QStringList kTypeList = { "AES", "ARIA", "SEED", "TDES", "HMAC" };

KeyAddDlg::KeyAddDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));

    connect( mRandKeyBtn, SIGNAL(clicked()), this, SLOT(clickRandKey()));

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeType()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKeyType()));
    connect( mIVTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeIVType()));

    connect( mKeyText, SIGNAL(textChanged(QString)), this, SLOT(changeKeyType()));
    connect( mIVText, SIGNAL(textChanged(QString)), this, SLOT(changeIVType()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyAddDlg::~KeyAddDlg()
{

}

void KeyAddDlg::readFile( const QString strName )
{
    QString strPath = berApplet->settingsMgr()->keyListPath();
    QString strFilePath = QString( "%1/%2" ).arg( strPath ).arg( strName );

    QFile keyFile( strFilePath );

    if( keyFile.open( QIODevice::ReadOnly | QIODevice::Text ) == false )
    {
        berApplet->elog( QString( "fail to read key: %1" ).arg( strFilePath ));
        return;
    }

    QString strLength;
    QString strAlg;
    QString strKey;
    QString strIV;
    QString strData;

    QTextStream in( &keyFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        if( strLine.length() < 2 || strLine.at(0) == '#' )
        {
            strLine = in.readLine();
            continue;
        }

        QStringList nameVal = strLine.split(":");
        if( nameVal.size() < 2 )
        {
            strLine = in.readLine();
            continue;
        }

        QString strFirst = nameVal.at(0).simplified();
        QString strSecond = nameVal.at(1).simplified();

        if( strFirst == "ALG" )
            strAlg = strSecond;
        else if( strFirst == "Length" )
            strLength = strSecond;
        else if( strFirst == "Key" )
            strKey = strSecond;
        else if( strFirst == "IV" )
            strIV = strSecond;

        strLine = in.readLine();
    }

    keyFile.close();

    mTypeCombo->clear();
    mKeyLenCombo->clear();
    mKeyTypeCombo->clear();
    mIVTypeCombo->clear();

    disconnect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT( changeType() ) );

    mKeyTypeCombo->addItem( "Hex" );
    mIVTypeCombo->addItem( "Hex" );

    mTypeCombo->addItem( strAlg );
    mKeyLenCombo->addItem( strLength );
    mNameText->setText( strName );
    mKeyText->setText( strKey );
    mIVText->setText( strIV );
}

void KeyAddDlg::setReadOnly()
{
    mRandKeyBtn->setEnabled(false);

    mNameText->setReadOnly(true);
    mKeyText->setReadOnly(true);
    mIVText->setReadOnly(true);

    mClearAllBtn->hide();
    mOKBtn->hide();
}

void KeyAddDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void KeyAddDlg::initUI()
{
    mTypeCombo->addItems( kTypeList );

    mKeyTypeCombo->addItems( kValueTypeList );
    mIVTypeCombo->addItems( kValueTypeList );
}

void KeyAddDlg::initialize()
{

}

void KeyAddDlg::clickClearAll()
{
    mNameText->clear();
    mKeyText->clear();
    mIVText->clear();
}

void KeyAddDlg::clickOK()
{
    int ret = 0;
    QString strName = mNameText->text();
    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    BIN binKey = {0,0};
    BIN binIV = {0,0};

    int nLen = mKeyLenCombo->currentText().toInt();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    if( strKey.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a key" ), this );
        mKeyText->setFocus();
        return;
    }

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );

    if( nLen != binKey.nLen )
    {
        berApplet->warningBox( tr( "Key Length is not %1 bytes").arg( nLen ), this );
        ret = -1;
        goto end;
    }

    ret = 0;

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );

    if( ret == 0 ) accept();
}

void KeyAddDlg::clickRandKey()
{
    BIN binRand = {0,0};
    int nLen = mKeyLenCombo->currentText().toInt();

    if( nLen > 0 )
    {
        JS_PKI_genRandom( nLen, &binRand );
        mKeyTypeCombo->setCurrentText( "Hex" );
        mKeyText->setText( getHexString( &binRand ) );
    }

    JS_BIN_reset( &binRand );
}

void KeyAddDlg::changeKeyType()
{
    QString strKey = mKeyText->text();

    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), strKey );
    mKeyLenText->setText( strLen );
}

void KeyAddDlg::changeIVType()
{
    QString strIV = mIVText->text();

    QString strLen = getDataLenString( mIVTypeCombo->currentText(), strIV );
    mIVLenText->setText( strLen );
}

void KeyAddDlg::changeType()
{
    QString strType = mTypeCombo->currentText();
    mKeyLenCombo->clear();
    mRandKeyBtn->setEnabled(true);

    if( strType == "AES" || strType == "ARIA" )
    {
        QStringList sLenList = { "16", "24", "32" };
        mKeyLenCombo->addItems( sLenList );
    }
    else if( strType == "SEED" || strType == "TDES" )
    {
        mKeyLenCombo->addItem( "16" );
    }
    else
    {
        mRandKeyBtn->setEnabled(false);
        mKeyLenCombo->addItem( "Any" );
    }
}
