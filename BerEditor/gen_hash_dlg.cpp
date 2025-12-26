/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "gen_hash_dlg.h"
#include "ui_gen_hash_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "common.h"
#include "hash_thread.h"
#include "js_error.h"

#include <QDialogButtonBox>
#include <QFileInfo>
#include <QDateTime>
#include <QElapsedTimer>

static const QString kSHAKE128 = "SHAKE128";
static const QString kSHAKE256 = "SHAKE256";

GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    pctx_ = NULL;
    thread_ = NULL;

    initUI();

    connect( mResetBtn, SIGNAL(clicked()), this, SLOT(clickReset()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(hashInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(hashUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(hashFinal()));

    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(digest()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clearInput()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clearOutput()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));

    connect( mOutputHashCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeOutputHash()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();
    mDigestBtn->setDefault(true);
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

GenHashDlg::~GenHashDlg()
{
//    delete ui;
    if( pctx_ ) JS_PKI_hashFree( &pctx_ );
    if( thread_ ) delete thread_;
}

void GenHashDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void GenHashDlg::dropEvent(QDropEvent *event)
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

void GenHashDlg::initUI()
{
    mInputTypeCombo->addItems( kDataTypeList );

    mOutputHashCombo->addItems( kHashList );
    mOutputHashCombo->addItem( kSHAKE128 );
    mOutputHashCombo->addItem( kSHAKE256 );

    mRunThreadCheck->setChecked(true);

    changeOutputHash();
}

void GenHashDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mOutputText->setPlaceholderText( tr("Hex value" ));
    mOutputHashCombo->setCurrentText( setMgr->defaultHash() );

    mSrcFileText->setPlaceholderText( tr( "Find the target file" ));

    mReqLenText->setText( QString("32"));
    mInputTab->setCurrentIndex(0);
}

int GenHashDlg::hashInit()
{
    int ret = 0;

    clickReset();

    QString strAlg = mOutputHashCombo->currentText();
    mOutputText->clear();

    ret = JS_PKI_hashInit( &pctx_, strAlg.toStdString().c_str() );
    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
        mInitText->setText( "OK" );
        mUpdateText->clear();
        mFinalText->clear();
        berApplet->log( QString( "initialization algorithm : %1" ).arg( strAlg ));
    }
    else
    {
        mInitText->setText( QString("%1").arg(ret));
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
    }

    update();
    return 0;
}

void GenHashDlg::hashUpdate()
{
    int ret = 0;

    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        ret = getBINFromString( &binSrc, strType, inputStr );
        FORMAT_WARN_GO(ret);
    }

    ret = JS_PKI_hashUpdate( pctx_, &binSrc );
    if( ret == 0 )
    {
        berApplet->log( QString( "Update input : %1" ).arg( getHexString(&binSrc)));
        mStatusLabel->setText( "Update OK" );

        int nUpdate = mUpdateText->text().toInt();

        if( nUpdate >= 0 )
        {
            nUpdate++;
            mUpdateText->setText( QString("%1").arg( nUpdate ));
        }
    }
    else
    {
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mUpdateText->setText( QString("%1").arg( ret ));
    }

end :
    JS_BIN_reset( &binSrc );
    update();
}

void GenHashDlg::hashFinal()
{
    int ret = 0;
    BIN binMD = {0,0};
    QString strHash = mOutputHashCombo->currentText();
    int nLen = mReqLenText->text().toInt();

    if( strHash == kSHAKE128 || strHash == kSHAKE256 )
        ret = JS_PKI_hashFinalXOR( pctx_, nLen, &binMD );
    else
        ret = JS_PKI_hashFinal( pctx_, &binMD );

    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binMD) );
        mStatusLabel->setText( "Final OK" );
        mFinalText->setText( "OK" );
        berApplet->log( QString("Final Digest : %1").arg( getHexString(&binMD)));
    }
    else
    {
        mStatusLabel->setText( QString("%1").arg(JERR(ret)) );
        mFinalText->setText( QString("%1").arg(ret) );
    }

    JS_PKI_hashFree( &pctx_ );
    pctx_ = NULL;
    JS_BIN_reset( &binMD );

    update();
}

void GenHashDlg::digest()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        clickDigest();
    else
    {
        if( mRunThreadCheck->isChecked() )
            clickDigestSrcFileThread();
        else
            clickDigestSrcFile();
    }
}

void GenHashDlg::clickReset()
{
    mStatusLabel->setText( tr("Status") );
    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();

    if( pctx_ )
    {
        JS_PKI_hashFree( &pctx_ );
        pctx_ = NULL;
    }
}

void GenHashDlg::clickDigest()
{
    int ret = 0;

    BIN binSrc = {0,0};
    BIN binHash = {0,0};

    qint64 us = 0;
    QElapsedTimer timer;

    QString inputStr = mInputText->toPlainText();
    QString strType = mInputTypeCombo->currentText();

    QString strHash = mOutputHashCombo->currentText();
    int nLen = mReqLenText->text().toInt();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        ret = getBINFromString( &binSrc, strType, inputStr );
        FORMAT_WARN_GO(ret);
    }

    if( strHash == kSHAKE128 || strHash == kSHAKE256 )
    {
        timer.start();
        ret = JS_PKI_genHashXOR( strHash.toStdString().c_str(), &binSrc, nLen, &binHash );
        us = timer.nsecsElapsed() / 1000;
    }
    else
    {
        timer.start();
        ret = JS_PKI_genHash( strHash.toStdString().c_str(), &binSrc, &binHash );
        us = timer.nsecsElapsed() / 1000;
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binHash, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free(pHex );

        mStatusLabel->setText( "Digest OK" );

        berApplet->logLine();
        berApplet->log( QString( "-- Hash [time: %1 ms]" ).arg( getMS( us )) );
        berApplet->logLine2();
        berApplet->log( QString( "Algorithm : %1" ).arg( strHash ));
        berApplet->log( QString( "Input     : %1" ).arg( getHexString( &binSrc) ));
        berApplet->log( QString( "Digest    : %1" ).arg(getHexString(&binHash)));

        if( strHash == kSHAKE128 || strHash == kSHAKE256 )
            berApplet->log( QString( "ReqLen    : %1" ).arg( nLen ));

        berApplet->logLine();
        berApplet->messageBox( tr("Digest value creation succeeded"), this );
    }
    else
    {
        mStatusLabel->setText( QString("Digest failed [%1]").arg(JERR(ret)) );
        berApplet->warningBox( tr("Failed to generate Digest value : %1").arg( JERR(ret)), this );
    }

end :
    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binHash);

    update();
}

void GenHashDlg::clearInput()
{
    mInputText->clear();
    update();
}

void GenHashDlg::clearOutput()
{
    mOutputText->clear();
    update();
}

void GenHashDlg::inputChanged()
{   
    QString strType = mInputTypeCombo->currentText();
    QString strLen = getDataLenString( strType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void GenHashDlg::outputChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void GenHashDlg::changeOutputHash()
{
    QString strHash = mOutputHashCombo->currentText();

    if( strHash == kSHAKE128 || strHash == kSHAKE256 )
    {
        mReqLenLabel->setEnabled(true);
        mReqLenText->setEnabled(true);
    }
    else
    {
        mReqLenLabel->setEnabled(false);
        mReqLenText->setEnabled(false);
    }
}

void GenHashDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mStatusLabel->setText( tr("Status"));

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();

    mHashProgBar->setValue(0);
    mFileSizeText->clear();
    mFileReadSizeText->clear();
}

void GenHashDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( getShowFileSize( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mHashProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileSizeText->clear();
    }
}

void GenHashDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();

    QString strSrcFile = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );
    setSrcFileInfo( strSrcFile );
}

void GenHashDlg::clickDigestSrcFile()
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

    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("Select input file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();
    if( fileSize <= 0 )
    {
        berApplet->warningBox( tr( "file is empty" ), this);
        return;
    }

    mHashProgBar->setValue( 0 );
    mFileSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;

    hashInit();
    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        berApplet->warningBox(tr( "failed to read file:%1").arg( strSrcFile ), this);
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

        ret = JS_PKI_hashUpdate( pctx_, &binPart );
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
        mHashProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        update();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mHashProgBar->setValue( 100 );

        if( ret == 0 )
        {
            hashFinal();
        }
    }

end :
    JS_BIN_reset( &binPart );
}

void GenHashDlg::clickDigestSrcFileThread()
{
    hashInit();
    startTask();
}

void GenHashDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new HashThread;
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
    if( fileSize <= 0 )
    {
        berApplet->warningBox( tr( "file is empty" ), this);
        return;
    }

    mFileSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect(thread_, &HashThread::taskFinished, this, &GenHashDlg::onTaskFinished);
    connect( thread_, &HashThread::taskUpdate, this, &GenHashDlg::onTaskUpdate);

    thread_->setCTX( pctx_ );
    thread_->setSrcFile( strSrcFile );

    thread_->start();
    berApplet->log("Task is running...");
}

void GenHashDlg::onTaskFinished() {
    berApplet->log("Task finished");
    mFinalText->setText( "OK" );

    hashFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void GenHashDlg::onTaskUpdate( qint64 nUpdate )
{
    int nCount = mUpdateText->text().toInt();

    if( nCount >= 0 )
    {
        nCount++;
        mUpdateText->setText( QString("%1").arg( nCount ));
    }

    berApplet->log( QString("Update: %1").arg( nUpdate ));
    qint64 nFileSize = mFileSizeText->text().toLongLong();
    int nPercent = (nUpdate * 100) / nFileSize;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mHashProgBar->setValue( nPercent );
}
