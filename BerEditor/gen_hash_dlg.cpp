/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

#include <QDialogButtonBox>
#include <QFileInfo>
#include <QDateTime>


GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    pctx_ = NULL;
    update_cnt_ = 0;
    thread_ = NULL;


    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(hashInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(hashUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(hashFinal()));

    connect( mDigestBtn, SIGNAL(clicked()), this, SLOT(digest()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clearInput()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clearOutput()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mTestBtn, SIGNAL(clicked()), this, SLOT(clickDigestSrcFile()));

    initialize();
    resize(width(), minimumSizeHint().height());

    mCloseBtn->setFocus();
}

GenHashDlg::~GenHashDlg()
{
//    delete ui;
    if( pctx_ ) JS_PKI_hashFree( &pctx_ );
    if( thread_ ) delete thread_;
}

void GenHashDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mOutputHashCombo->addItems( kHashList );
    mOutputHashCombo->setCurrentText( setMgr->defaultHash() );

    mInputTab->setCurrentIndex(0);

#if defined(QT_DEBUG)
    mTestBtn->show();
#else
    mTestBtn->hide();
#endif
}

void GenHashDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
}

int GenHashDlg::hashInit()
{
    int ret = 0;

    if( pctx_ )
    {
        JS_PKI_hashFree( &pctx_ );
        pctx_ = NULL;
    }
    update_cnt_ = 0;

    QString strAlg = mOutputHashCombo->currentText();
    mOutputText->clear();

    ret = JS_PKI_hashInit( &pctx_, strAlg.toStdString().c_str() );
    if( ret == 0 )
    {
        mStatusLabel->setText( "Initialization successful" );

        berApplet->log( QString( "initialization algorithm : %1" ).arg( strAlg ));
    }
    else
        mStatusLabel->setText( QString("Initialization failed [%1]").arg(ret) );

    repaint();
    return 0;
}

void GenHashDlg::hashUpdate()
{
    int ret = 0;
    int nDataType = DATA_STRING;

    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        if( mInputStringRadio->isChecked() )
            nDataType = DATA_STRING;
        else if( mInputHexRadio->isChecked() )
        {
            nDataType = DATA_HEX;
        }
        else if( mInputBase64Radio->isChecked() )
        {
            nDataType = DATA_BASE64;
        }

        getBINFromString( &binSrc, nDataType, inputStr );
    }

    ret = JS_PKI_hashUpdate( pctx_, &binSrc );
    if( ret == 0 )
    {
        update_cnt_++;
        berApplet->log( QString( "Update input : %1" ).arg( getHexString(&binSrc)));
        appendStatusLabel( "|Update OK" );
    }
    else
        mStatusLabel->setText( QString("Update failed [%1]").arg(ret) );

    JS_BIN_reset( &binSrc );
    repaint();
}

void GenHashDlg::hashFinal()
{
    int ret = 0;
    BIN binMD = {0,0};

    ret = JS_PKI_hashFinal( pctx_, &binMD );
    if( ret == 0 )
    {
        mOutputText->setPlainText( getHexString( &binMD) );
        appendStatusLabel( "|Final OK" );

        berApplet->log( QString("Final Digest : %1").arg( getHexString(&binMD)));
    }
    else
    {
        mStatusLabel->setText( QString("Final failed [%1]").arg(ret) );
    }

    JS_PKI_hashFree( &pctx_ );
    pctx_ = NULL;
    JS_BIN_reset( &binMD );

    repaint();
}

void GenHashDlg::digest()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        clickDigest();
    else
        clickDigestSrcFileThread();
}

void GenHashDlg::clickDigest()
{
    int ret = 0;

    BIN binSrc = {0,0};
    BIN binHash = {0,0};
    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        int nDataType = DATA_STRING;
        if( mInputStringRadio->isChecked() )
            nDataType = DATA_STRING;
        else if( mInputHexRadio->isChecked() )
        {
            nDataType = DATA_HEX;
        }
        else if( mInputBase64Radio->isChecked() )
        {
            nDataType = DATA_BASE64;
        }

        getBINFromString( &binSrc, nDataType, inputStr );
    }

    QString strHash = mOutputHashCombo->currentText();

    ret = JS_PKI_genHash( strHash.toStdString().c_str(), &binSrc, &binHash );
    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binHash, &pHex );
        mOutputText->setPlainText( pHex );
        if( pHex ) JS_free(pHex );

        mStatusLabel->setText( "Digest OK" );

        berApplet->logLine();
        berApplet->log( "-- Hash" );
        berApplet->logLine();
        berApplet->log( QString( "Algorithm : %1" ).arg( strHash ));
        berApplet->log( QString( "Input     : %1" ).arg( getHexString( &binSrc) ));
        berApplet->log( QString( "Digest    : %1" ).arg(getHexString(&binHash)));
        berApplet->logLine();
    }
    else
    {
        mStatusLabel->setText( QString("Digest failed [%1]").arg(ret) );
    }

    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binHash);

    repaint();
}

void GenHashDlg::clearInput()
{
    mInputText->clear();
    repaint();
}

void GenHashDlg::clearOutput()
{
    mOutputText->clear();
    repaint();
}

void GenHashDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void GenHashDlg::outputChanged()
{
    int nLen = getDataLen( DATA_HEX, mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void GenHashDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mStatusLabel->clear();

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();

    mHashProgBar->setValue(0);
    mFileSizeText->clear();
    mFileReadSizeText->clear();
}

void GenHashDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();

    QString strSrcFile = findFile( this, JS_FILE_TYPE_ALL, strPath );

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
        mHashProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileSizeText->clear();
    }
}

void GenHashDlg::clickDigestSrcFile()
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
        berApplet->warningBox( tr("Select input file"), this );
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mHashProgBar->setValue( 0 );
    mFileSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );


    nLeft = fileSize;

    hashInit();
    FILE *fp = fopen( strSrcFile.toLocal8Bit().toStdString().c_str(), "rb" );

    if( fp == NULL )
    {
        berApplet->elog( QString( "failed to read file:%1").arg( strSrcFile ));
        goto end;
    }

    berApplet->log( QString( "TotalSize: %1 BlockSize: %2").arg( fileSize).arg( nPartSize ));

    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        ret = JS_PKI_hashUpdate( pctx_, &binPart );
        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update : %1").arg(ret));
            break;
        }

        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mHashProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        repaint();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mHashProgBar->setValue( 100 );

        if( ret == 0 )
        {
            QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
            appendStatusLabel( strStatus );
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
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

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

    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    hashFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void GenHashDlg::onTaskUpdate( int nUpdate )
{
    berApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mHashProgBar->setValue( nPercent );
}
