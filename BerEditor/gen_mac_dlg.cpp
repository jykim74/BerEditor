#include <QStringList>
#include <QButtonGroup>
#include <QFileInfo>
#include <QDateTime>

#include "js_ber.h"
#include "gen_mac_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

#define JS_TYPE_HMAC    0
#define JS_TYPE_CMAC    1
#define JS_TYPE_GMAC    2

static QStringList cryptList = {
    "AES",
    "ARIA",
    "DES3",
    "SM4"
};

static QStringList gmacList = {
    "AES",
    "ARIA"
};

static QStringList keyTypes = {
    "String",
    "Hex",
    "Base64"
};

GenMacDlg::GenMacDlg(QWidget *parent) :
    QDialog(parent)
{
    hctx_ = NULL;
    type_ = 0;
    group_ = new QButtonGroup;
    setupUi(this);

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(macInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(macUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(macFinal()));

    connect( mMACBtn, SIGNAL(clicked()), this, SLOT(mac()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(inputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(outputClear()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mHMACRadio, SIGNAL(clicked()), this, SLOT(checkHMAC()));
    connect( mCMACRadio, SIGNAL(clicked()), this, SLOT(checkCMAC()));
    connect( mGMACRadio, SIGNAL(clicked()), this, SLOT(checkGMAC()));

    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();

    mCloseBtn->setFocus();
}

GenMacDlg::~GenMacDlg()
{
    if( group_ ) delete group_;
    freeCTX();
}

void GenMacDlg::initialize()
{
    mKeyTypeCombo->addItems( keyTypes );

    group_->addButton( mHMACRadio );
    group_->addButton( mCMACRadio );
    group_->addButton( mGMACRadio );

    mInputTab->setCurrentIndex(0);

    checkHMAC();
}

void GenMacDlg::freeCTX()
{
    if( hctx_ )
    {
        if( type_ == JS_TYPE_CMAC )
            JS_PKI_cmacFree( &hctx_ );
        else if( type_ == JS_TYPE_HMAC)
            JS_PKI_hmacFree( &hctx_ );
        else if( type_ == JS_TYPE_GMAC )
            JS_PKI_encryptGCMFree( &hctx_ );

        hctx_ = NULL;
    }

    type_ = 0;
}

void GenMacDlg::macInit()
{
    int ret = 0;


    BIN binKey = {0,0};

    QString strKey = mKeyText->text();

    if( mKeyTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );


   QString strAlg = mAlgTypeCombo->currentText();

   if( mCMACRadio->isChecked() )
   {
        QString strSymAlg = getSymAlg( strAlg, "CBC", binKey.nLen );

        ret = JS_PKI_cmacInit( &hctx_, strSymAlg.toStdString().c_str(), &binKey );
        if( ret == 0 ) type_ = JS_TYPE_CMAC;
   }
   else if( mHMACRadio->isChecked() )
   {
        ret = JS_PKI_hmacInit( &hctx_, strAlg.toStdString().c_str(), &binKey );
        if( ret == 0 ) type_ = JS_TYPE_HMAC;
   }
   else if( mGMACRadio->isChecked() )
   {
       BIN binIV = {0,0};
       QString strSymAlg = getSymAlg( strAlg, "gcm", binKey.nLen );
       JS_BIN_setChar( &binIV, 0x00, 16 );
       ret = JS_PKI_encryptGCMInit( &hctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, NULL );
       if( ret == 0 ) type_ = JS_TYPE_GMAC;
       JS_BIN_reset( &binIV );
   }

   berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
   berApplet->log( QString( "Key       : %1" ).arg( getHexString( &binKey )));

   if( ret == 0 )
   {
       mStatusLabel->setText( "Init OK" );
   }
   else
       mStatusLabel->setText( QString("Init fail:%1").arg( ret ) );

   JS_BIN_reset( &binKey );
   repaint();
}

void GenMacDlg::macUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
        if( mInputStringRadio->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
        else if( mInputHexRadio->isChecked() )
        {
            strInput.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Radio->isChecked() )
        {
            strInput.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
        }
    }

    if( mCMACRadio->isChecked() )
    {
        if( type_ != JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_cmacUpdate( hctx_, &binSrc );
    }
    else if( mHMACRadio->isChecked() )
    {
        if( type_ != JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_hmacUpdate( hctx_, &binSrc );
    }
    else if( mGMACRadio->isChecked() )
    {
        if( type_ != JS_TYPE_GMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binSrc );
    }

    berApplet->log( QString( "Update Src : %1" ).arg( getHexString(&binSrc)));

    if( ret == 0 )
    {
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( QString("Updata fail:%1").arg(ret) );

    JS_BIN_reset( &binSrc );
    repaint();
}

void GenMacDlg::macFinal()
{
    int ret = 0;
    BIN binMAC = {0,0};

    if( mCMACRadio->isChecked() )
    {
        if( type_ != JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_cmacFinal( hctx_, &binMAC );
    }
    else if( mHMACRadio->isChecked() )
    {
        if( type_ != JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_hmacFinal( hctx_, &binMAC );
    }
    else if( mGMACRadio->isChecked() )
    {
        BIN binEnc = {0,0};
        if( type_ != JS_TYPE_GMAC )
        {
            berApplet->elog( "Invalid context type" );
            return;
        }

        ret = JS_PKI_encryptGCMFinal( hctx_, &binEnc, 16, &binMAC );
        JS_BIN_reset( &binEnc );
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMAC, &pHex );
        mOutputText->setPlainText( pHex );
        mStatusLabel->setText( "Final OK" );
        JS_free( pHex );

        berApplet->log( QString( "Final Digest : %1" ).arg( getHexString( &binMAC )) );
    }
    else
        mStatusLabel->setText( QString("Final fail:%1").arg(ret) );

    freeCTX();

    JS_BIN_reset( &binMAC );

    repaint();
}

void GenMacDlg::mac()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        clickMAC();
    else
        clickMACSrcFile();
}

void GenMacDlg::clickMAC()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binMAC = {0,0};

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
    {
        if( mInputStringRadio->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)strInput.toStdString().c_str(), strInput.length() );
        else if( mInputHexRadio->isChecked() )
        {
            strInput.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( strInput.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Radio->isChecked() )
        {
            strInput.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( strInput.toStdString().c_str(), &binSrc );
        }
    }

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "You have to insert key"), this );
        JS_BIN_reset(&binSrc);
        return;
    }

    if( mKeyTypeCombo->currentIndex() == 0 )
        JS_BIN_set( &binKey, (unsigned char *)strKey.toStdString().c_str(), strKey.length() );
    else if( mKeyTypeCombo->currentIndex() == 1 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    else if( mKeyTypeCombo->currentIndex() == 2 )
        JS_BIN_decodeBase64( strKey.toStdString().c_str(), &binKey );


   QString strAlg = mAlgTypeCombo->currentText();

   if( mCMACRadio->isChecked() )
   {
       QString strSymAlg = getSymAlg( strAlg, "CBC", binKey.nLen );
       ret = JS_PKI_genCMAC( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );

       berApplet->log( QString( "Algorithm : %1" ).arg( strSymAlg ));
   }
   else if( mHMACRadio->isChecked() )
   {
       berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
       ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
   }
   else if( mGMACRadio->isChecked() )
   {
        berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
        ret = JS_PKI_genGMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
   }

   if( ret == 0 )
   {
       char *pHex = NULL;
       JS_BIN_encodeHex( &binMAC, &pHex );
       mOutputText->setPlainText( pHex );
       mStatusLabel->setText( "MAC OK" );
       if( pHex ) JS_free(pHex);

       berApplet->log( QString( "Input : %1" ).arg(getHexString(&binSrc)));
       berApplet->log( QString( "Key   : %1" ).arg( getHexString(&binKey)));
       berApplet->log( QString( "MAC   : %1" ).arg( getHexString(&binMAC)));
   }
   else
   {
       mStatusLabel->setText( QString("MAC fail:%1").arg(ret) );
   }

   JS_BIN_reset(&binSrc);
   JS_BIN_reset(&binKey);
   JS_BIN_reset(&binMAC);

   repaint();
}

void GenMacDlg::clickFindSrcFile()
{
    QString strPath;
    QString strSrcFile = findFile( this, JS_FILE_TYPE_BER, strPath );

    if( strSrcFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strSrcFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strSrcFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mMACProgBar->setValue(0);
    }
}

void GenMacDlg::clickMACSrcFile()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;
    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};


    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("You have to find src file"), this );
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mMACProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    macInit();
    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        if( mCMACRadio->isChecked() )
        {
            ret = JS_PKI_cmacUpdate( hctx_, &binPart );
        }
        else if( mHMACRadio->isChecked() )
        {
            ret = JS_PKI_hmacUpdate( hctx_, &binPart );
        }
        else if( mGMACRadio->isChecked() )
        {
            ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binPart );
        }

        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mMACProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        repaint();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mMACProgBar->setValue( 100 );

        if( ret == 0 )
        {
            macFinal();
        }
    }

end :
    freeCTX();
    JS_BIN_reset( &binPart );
}

void GenMacDlg::inputClear()
{
    mInputText->clear();
    repaint();
}

void GenMacDlg::outputClear()
{
    mOutputText->clear();
    repaint();
}

void GenMacDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::outputChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::keyChanged()
{
    int nLen = getDataLen( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(nLen));
}

void GenMacDlg::checkHMAC()
{
    mHMACRadio->setChecked(true);

    mAlgTypeCombo->clear();

    mAlgTypeCombo->addItems( kHashList );
    mAlgTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
}

void GenMacDlg::checkCMAC()
{
    mCMACRadio->setChecked(true);

    mAlgTypeCombo->clear();
    mAlgTypeCombo->addItems( cryptList );
}

void GenMacDlg::checkGMAC()
{
    mGMACRadio->setChecked(true);
    mAlgTypeCombo->clear();
    mAlgTypeCombo->addItems( gmacList );
}

void GenMacDlg::clickClearDataAll()
{
    mInputText->clear();
    mKeyText->clear();
    mOutputText->clear();
    mStatusLabel->clear();

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();

    mFileTotalSizeText->clear();
    mFileReadSizeText->clear();
    mMACProgBar->setValue(0);
}
