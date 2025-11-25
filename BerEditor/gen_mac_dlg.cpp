/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include <QStringList>
#include <QButtonGroup>
#include <QFileInfo>
#include <QDateTime>
#include <QElapsedTimer>

#include "js_ber.h"
#include "gen_mac_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "mac_thread.h"
#include "js_error.h"
#include "key_list_dlg.h"


static QString sMethodHMAC = "HMAC";
static QString sMethodCMAC = "CMAC";
static QString sMethodGMAC = "GMAC";

static QStringList sMethodList = { sMethodHMAC, sMethodCMAC, sMethodGMAC };

GenMacDlg::GenMacDlg(QWidget *parent) :
    QDialog(parent)
{
    hctx_ = NULL;
    type_ = 0;

    thread_ = NULL;

    setupUi(this);
    setAcceptDrops(true);

    initUI();

    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(macInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(macUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(macFinal()));
    connect( mResetBtn, SIGNAL(clicked()), this, SLOT(clickReset()));

    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(mac()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(inputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(outputClear()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mGenerateRadio, SIGNAL(clicked()), this, SLOT(checkGenerate()));
    connect( mVerifyRadio, SIGNAL(clicked()), this, SLOT(checkVerify()));
    connect( mMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMethod()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));

    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(ivChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));

    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();
    mRunBtn->setDefault(true);
    mInputText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);

    mInputClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GenMacDlg::~GenMacDlg()
{
    if( thread_ ) delete thread_;

    freeCTX();
}

void GenMacDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void GenMacDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));
            mInputTab->setCurrentIndex(1);
            setSrcFileInfo( url.toLocalFile() );
            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void GenMacDlg::initUI()
{
    mInputTypeCombo->addItems( kDataTypeList );
    mKeyTypeCombo->addItems( kDataTypeList );
    mIVTypeCombo->addItems( kDataTypeList );

    mMethodCombo->addItems( sMethodList );
    mRunThreadCheck->setChecked(true);

    mOutputText->setPlaceholderText( tr("Hex value" ));
    mKeyText->setPlaceholderText( tr( "Select KeyList key"));
    mSrcFileText->setPlaceholderText( tr( "Find the target file" ));
}

void GenMacDlg::initialize()
{
    mInputTab->setCurrentIndex(0);
    mGenerateRadio->click();
    changeMethod();
}

void GenMacDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mMACProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
    }
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

int GenMacDlg::macInit()
{
    int ret = 0;

    BIN binKey = {0,0};

    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    QString strAlg = mAlgTypeCombo->currentText();
    QString strMethod = mMethodCombo->currentText();

    clickReset();

    if( strKey.length() < 1 )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));
        keyList.setManage( false );

        if( keyList.exec() == QDialog::Accepted )
        {
            strKey = keyList.getKey();
            strIV = keyList.getIV();

            if( strKey.length() > 0 )
            {
                mKeyTypeCombo->setCurrentText( "Hex" );
                mKeyText->setText( strKey );
            }

            if( strIV.length() > 0 )
            {
                mIVTypeCombo->setCurrentText( "Hex" );
                mIVText->setText( strIV );
            }
        }

        if( strKey.length() < 1 )
        {
            berApplet->warningBox( tr("Enter a key value"), this );
            mKeyText->setFocus();
            return JSR_ERR;
        }
    }

    ret = getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
    FORMAT_WARN_GO( ret );


    if( mGenerateRadio->isChecked() == true )
        mOutputText->clear();

    if( strMethod == sMethodCMAC )
    {
        QString strSymAlg;
        ret = getSymAlg( strAlg, "CBC", binKey.nLen, strSymAlg );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get cipher name: %1").arg( JERR(ret)), this );
            goto end;
        }

         ret = JS_PKI_cmacInit( &hctx_, strSymAlg.toStdString().c_str(), &binKey );
         if( ret == 0 ) type_ = JS_TYPE_CMAC;
    }
    else if( strMethod == sMethodHMAC )
    {
         ret = JS_PKI_hmacInit( &hctx_, strAlg.toStdString().c_str(), &binKey );
         if( ret == 0 ) type_ = JS_TYPE_HMAC;
    }
    else if( strMethod == sMethodGMAC )
    {
        BIN binIV = {0,0};
        QString strSymAlg;

        QString strIV = mIVText->text();

        ret = getSymAlg( strAlg, "gcm", binKey.nLen, strSymAlg );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get cipher name: %1").arg( JERR(ret)), this );
            goto end;
        }

        if( strIV.length() < 1 )
        {
            berApplet->warningBox( tr("Enter a IV value"), this );
            mIVText->setFocus();
            ret = JSR_ERR;
            goto end;
        }

        ret = getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
        FORMAT_WARN_GO( ret );


        ret = JS_PKI_encryptGCMInit( &hctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, NULL );
        if( ret == 0 ) type_ = JS_TYPE_GMAC;
    }

    berApplet->log( QString( "Init" ));
    berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
    berApplet->log( QString( "Key       : %1" ).arg( getHexString( &binKey )));

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
        mInitText->setText( "OK" );
    }
    else
    {
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mInitText->setText( QString("%1").arg(ret));
    }

end :
    JS_BIN_reset( &binKey );
    update();
    return ret;
}

void GenMacDlg::macUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};

    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();
    QString strMethod = mMethodCombo->currentText();

    if( strInput.length() > 0 )
    {
        ret = getBINFromString( &binSrc, strType, strInput );
        FORMAT_WARN_GO(ret);
    }

    if( strMethod == sMethodCMAC )
    {
        if( type_ != JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid type" );
            return;
        }

        ret = JS_PKI_cmacUpdate( hctx_, &binSrc );
    }
    else if( strMethod == sMethodHMAC )
    {
        if( type_ != JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid type" );
            return;
        }

        ret = JS_PKI_hmacUpdate( hctx_, &binSrc );
    }
    else if( strMethod == sMethodGMAC )
    {
        if( type_ != JS_TYPE_GMAC )
        {
            berApplet->elog( "Invalid type" );
            return;
        }

        ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binSrc );
    }

    berApplet->log( QString( "Update input : %1" ).arg( getHexString(&binSrc)));

    if( ret == 0 )
    {
        mStatusLabel->setText( QString("Update OK") );
        int nCount = mUpdateText->text().toInt();
        if( nCount >= 0 )
        {
            nCount++;
            mUpdateText->setText( QString("%1").arg(nCount));
        }
    }
    else
    {
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mUpdateText->setText( QString("%1").arg(ret));
    }

end :
    JS_BIN_reset( &binSrc );
    update();
}

void GenMacDlg::macFinal()
{
    int ret = 0;
    BIN binMAC = {0,0};
    BIN binInMAC = {0,0};
    QString strMethod = mMethodCombo->currentText();
    QString strOutput = mOutputText->toPlainText();

    if( mVerifyRadio->isChecked() == true )
    {
        if( strOutput.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter MAC value" ), this );
            mOutputText->setFocus();
            return;
        }

        ret = getBINFromString( &binInMAC, DATA_HEX, strOutput );
        FORMAT_WARN_GO( ret );
    }

    if( strMethod == sMethodCMAC )
    {
        if( type_ != JS_TYPE_CMAC )
        {
            berApplet->elog( "Invalid type" );
            goto end;
        }

        ret = JS_PKI_cmacFinal( hctx_, &binMAC );
    }
    else if( strMethod == sMethodHMAC )
    {
        if( type_ != JS_TYPE_HMAC )
        {
            berApplet->elog( "Invalid type" );
            goto end;
        }

        ret = JS_PKI_hmacFinal( hctx_, &binMAC );
    }
    else if( strMethod == sMethodGMAC )
    {
        BIN binEnc = {0,0};
        if( type_ != JS_TYPE_GMAC )
        {
            berApplet->elog( "Invalid type" );
            goto end;
        }

        ret = JS_PKI_encryptGCMFinal( hctx_, &binEnc, 16, &binMAC );
        JS_BIN_reset( &binEnc );
    }

    if( ret == JSR_OK )
    {
        if( mGenerateRadio->isChecked() == true )
            mOutputText->setPlainText( getHexString( &binMAC) );

        mFinalText->setText( "OK" );

        berApplet->log( QString( "Final Digest : %1" ).arg( getHexString( &binMAC )) );
        if( mVerifyRadio->isChecked() == true )
        {
            if( verifyMAC( &binMAC, &binInMAC ) == JSR_VERIFY )
            {
                mStatusLabel->setText( QString( "MAC good" ));
                berApplet->messageBox( tr("MAC verification successful"), this );
            }
            else
            {
                mStatusLabel->setText( QString("MAC %1").arg(JERR( JSR_INVALID_VALUE )));
                berApplet->warningBox( tr( "Failed to verify MAC value: %1" ).arg(JERR( JSR_INVALID_VALUE )), this );
            }
        }
        else
        {
            mStatusLabel->setText( "Final OK" );
            berApplet->messageBox( tr("MAC value generation succeeded"), this );
        }
    }
    else
    {
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mFinalText->setText( QString("%1").arg(ret));

        if( mVerifyRadio->isChecked() == true )
        {
            berApplet->warningBox( tr( "Failed to verify MAC value: %1" ).arg(JERR(ret)), this );
        }
        else
        {
            berApplet->warningBox( tr( "Failed to generate MAC value: %1" ).arg(JERR(ret)), this );
        }
    }

end :
    freeCTX();

    JS_BIN_reset( &binMAC );
    JS_BIN_reset( &binInMAC );
}

void GenMacDlg::clickReset()
{
    mStatusLabel->setText( tr("Status") );

    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();

    freeCTX();
}

void GenMacDlg::mac()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        clickMAC();
    else
    {
        if( mRunThreadCheck->isChecked() )
            clickMacSrcFileThread();
        else
            clickMACSrcFile();
    }
}

int GenMacDlg::verifyMAC( const BIN *pMAC, const BIN *pInMAC )
{
    bool bSame = false;
    QString strMethod = mMethodCombo->currentText();

    if( pMAC == NULL || pInMAC == NULL ) return JSR_INVALID;

    if( strMethod == sMethodGMAC )
    {
        if( pMAC->nLen >= pInMAC->nLen )
        {
            if( pInMAC->nLen >= 4 && pInMAC->nLen <= 16 )
            {
                if( memcmp( pInMAC->pVal, pInMAC->pVal, pInMAC->nLen ) == 0 )
                    bSame = true;
            }
        }
    }
    else
    {
        if( JS_BIN_cmp( pMAC, pInMAC ) == 0 )
            bSame = true;
    }

    if( bSame == true )
        return JSR_VERIFY;
    else
        return JSR_INVALID;
}

void GenMacDlg::clickMAC()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binMAC = {0,0};
    BIN binInMAC = {0,0};
    BIN binIV = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();
    QString strOutput = mOutputText->toPlainText();

    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    QString strAlg = mAlgTypeCombo->currentText();
    QString strMethod = mMethodCombo->currentText();

    if( mVerifyRadio->isChecked() == true )
    {
        if( strOutput.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter MAC value" ), this );
            mOutputText->setFocus();
            return;
        }

        ret = getBINFromString( &binInMAC, DATA_HEX, strOutput );
        FORMAT_WARN_GO(ret);
    }

    if( strInput.length() > 0 )
    {
        ret = getBINFromString( &binSrc, strType, strInput );
        FORMAT_WARN_GO( ret );
    }

    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));
        keyList.setManage( false );

        if( keyList.exec() == QDialog::Accepted )
        {
            strKey = keyList.getKey();
            strIV = keyList.getIV();

            if( strKey.length() > 0 )
            {
                mKeyTypeCombo->setCurrentText( "Hex" );
                mKeyText->setText( strKey );
            }

            if( strIV.length() > 0 )
            {
                mIVTypeCombo->setCurrentText( "Hex" );
                mIVText->setText( strIV );
            }
        }

        if( strKey.isEmpty() )
        {
            berApplet->warningBox( tr( "Please Enter a key value"), this );
            JS_BIN_reset(&binSrc);
            mKeyText->setFocus();
            return;
        }
    }

    ret = getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
    FORMAT_WARN_GO( ret );

    if( strMethod == sMethodCMAC )
    {
        QString strSymAlg;
        ret = getSymAlg( strAlg, "CBC", binKey.nLen, strSymAlg );
        if( ret != JSR_OK )
        {
            berApplet->warningBox( tr( "failed to get cipher name: %1").arg( JERR(ret)), this );
            goto end;
        }

        timer.start();
        ret = JS_PKI_genCMAC( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( strMethod == sMethodHMAC )
    {
        timer.start();
        ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
        us = timer.nsecsElapsed() / 1000;
    }
    else if( strMethod == sMethodGMAC )
    {
        QString strIV = mIVText->text();

        if( strIV.length() < 1 )
        {
             berApplet->warningBox( tr("Enter a IV value"), this );
             mIVText->setFocus();
             ret = JSR_ERR;
             goto end;
        }

        ret = getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
        FORMAT_WARN_GO( ret );

        timer.start();
        ret = JS_PKI_genGMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binMAC );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret == JSR_OK )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMAC, &pHex );

        if( mGenerateRadio->isChecked() == true ) mOutputText->setPlainText( pHex );

        if( pHex ) JS_free(pHex);

        berApplet->logLine();
        berApplet->log( QString( "-- MAC [time: %1 ms]" ).arg( getMS( us )) );
        berApplet->logLine2();
        berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
        berApplet->log( QString( "Input : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Key   : %1" ).arg( getHexString(&binKey)));
        berApplet->log( QString( "MAC   : %1" ).arg( getHexString(&binMAC)));
        berApplet->logLine();

        if( mVerifyRadio->isChecked() == true )
        {
            if( verifyMAC( &binMAC, &binInMAC ) == JSR_VERIFY )
            {
                mStatusLabel->setText( "Verify OK" );
                berApplet->messageBox( tr("MAC verification successful"), this );
            }
            else
            {
                mStatusLabel->setText( QString("Verify failed: %1").arg(JERR( JSR_INVALID_VALUE )));
                berApplet->warningBox( tr( "Failed to verify MAC value: %1" ).arg(JERR( JSR_INVALID_VALUE )), this );
            }
        }
        else
        {
            mStatusLabel->setText( "MAC OK" );
            berApplet->messageBox( tr("MAC value generation succeeded"), this );
        }
    }
    else
    {
        if( mVerifyRadio->isChecked() == true )
        {
            mStatusLabel->setText( QString("MAC verification failed: %1").arg(JERR(ret)) );
            berApplet->warningBox( tr( "Failed to verify MAC value: %1" ).arg(JERR(ret)), this );
        }
        else
        {
            mStatusLabel->setText( QString("MAC failure [%1]").arg(JERR(ret)) );
            berApplet->warningBox( tr( "Failed to generate MAC value: %1" ).arg(JERR(ret)), this );
        }
    }

end :
    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binKey);
    JS_BIN_reset(&binMAC);
    JS_BIN_reset(&binIV);
    JS_BIN_reset( &binInMAC );
}

void GenMacDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();

    QString strSrcFile = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );
    setSrcFileInfo( strSrcFile );
}

void GenMacDlg::clickMACSrcFile()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    qint64 nOffset = 0;
    int nPercent = 0;

    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};
    QString strMethod = mMethodCombo->currentText();


    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("Select a input file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mMACProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    if( macInit() != 0 )
    {
        berApplet->elog( "MAC initialization failed" );
        return;
    }

    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        berApplet->elog( QString( "failed to read file:%1").arg( strSrcFile ));
        goto end;
    }

    berApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));

    while( nLeft > 0 )
    {
        int nUpdate = mUpdateText->text().toInt();

        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            berApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        if( strMethod == sMethodCMAC )
        {
            ret = JS_PKI_cmacUpdate( hctx_, &binPart );
        }
        else if( strMethod == sMethodHMAC )
        {
            ret = JS_PKI_hmacUpdate( hctx_, &binPart );
        }
        else if( strMethod == sMethodGMAC )
        {
            ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binPart );
        }

        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update : %1").arg(ret));
            mStatusLabel->setText( QString("%1").arg(JERR(ret)));
            mUpdateText->setText( QString("%1").arg(ret));
            break;
        }

        if( nUpdate >= 0 )
        {
            nUpdate++;
            mStatusLabel->setText( "Update OK" );
            mUpdateText->setText( QString("%1").arg(nUpdate));
        }

        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mMACProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
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
    update();
}

void GenMacDlg::outputClear()
{
    mOutputText->clear();
    update();
}

void GenMacDlg::inputChanged()
{
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void GenMacDlg::outputChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void GenMacDlg::keyChanged()
{
    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(strLen));
}

void GenMacDlg::ivChanged()
{
    QString strLen = getDataLenString( mIVTypeCombo->currentText(), mIVText->text() );
    mIVLenText->setText( QString("%1").arg(strLen));
}

void GenMacDlg::checkGenerate()
{
    mRunBtn->setText( tr("MAC"));

    mOutputText->setReadOnly(true);
    mOutputText->setStyleSheet( kReadOnlyStyle );
}

void GenMacDlg::checkVerify()
{
    mRunBtn->setText( tr("Verify"));

    mOutputText->setReadOnly(false);
    mOutputText->setStyleSheet( "" );
}

void GenMacDlg::changeMethod()
{
    QString strMethod = mMethodCombo->currentText();

    if( strMethod == sMethodHMAC )
    {
        mIVLabel->setEnabled( false );
        mIVTypeCombo->setEnabled( false );
        mIVText->setEnabled( false );
        mIVLenText->setEnabled( false );

        mAlgTypeCombo->clear();
        mAlgTypeCombo->addItems( kHashList );
        mAlgTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
    }
    else if( strMethod == sMethodCMAC )
    {
        mIVLabel->setEnabled(false);
        mIVTypeCombo->setEnabled(false);
        mIVText->setEnabled(false);
        mIVLenText->setEnabled( false );

        mAlgTypeCombo->clear();
        mAlgTypeCombo->addItems( kBaseSymList );
    }
    else if( strMethod == sMethodGMAC )
    {
        mIVLabel->setEnabled(true);
        mIVTypeCombo->setEnabled(true);
        mIVText->setEnabled(true);
        mIVLenText->setEnabled(true);

        mAlgTypeCombo->clear();
        mAlgTypeCombo->addItems( kBaseSymList );
    }
}

void GenMacDlg::clickClearDataAll()
{
    mInputText->clear();
    mKeyText->clear();
    mIVText->clear();
    mOutputText->clear();
    mStatusLabel->setText( tr("Status" ));

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();

    mFileTotalSizeText->clear();
    mFileReadSizeText->clear();
    mMACProgBar->setValue(0);
}

void GenMacDlg::clickMacSrcFileThread()
{
    if( macInit() != 0 )
    {
        berApplet->elog( "MAC initialization failed" );
        return;
    }

    startTask();
}

void GenMacDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new MacThread;
    QString strSrcFile = mSrcFileText->text();

    if( strSrcFile.length() < 1)
    {
        berApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect( thread_, &MacThread::taskFinished, this, &GenMacDlg::onTaskFinished);
    connect( thread_, &MacThread::taskUpdate, this, &GenMacDlg::onTaskUpdate);

    thread_->setType( type_ );
    thread_->setCTX( hctx_ );
    thread_->setSrcFile( strSrcFile );
    thread_->start();

    berApplet->log("Task is running...");
}

void GenMacDlg::onTaskFinished()
{
    berApplet->log("Task finished");

    macFinal();
    freeCTX();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void GenMacDlg::onTaskUpdate( qint64 nUpdate )
{
    int nCount = mUpdateText->text().toInt();
    if( nCount >= 0 )
    {
        nCount++;
        mUpdateText->setText( QString("%1").arg(nCount));
    }

    berApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileTotalSizeText->text().toLongLong();
    int nPercent = int( (nUpdate * 100) / nFileSize );

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mMACProgBar->setValue( nPercent );
}
