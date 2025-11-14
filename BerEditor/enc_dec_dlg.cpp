/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>
#include <QButtonGroup>
#include <QElapsedTimer>

#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "enc_dec_thread.h"
#include "key_list_dlg.h"

static QStringList modeList = {
    JS_PKI_SYM_MODE_CBC, JS_PKI_SYM_MODE_ECB, JS_PKI_SYM_MODE_CTR, JS_PKI_SYM_MODE_CFB,
    JS_PKI_SYM_MODE_OFB
};

static QStringList modeAEList = {
    JS_PKI_SYM_MODE_GCM, JS_PKI_SYM_MODE_CCM
};

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    ctx_ = NULL;
    thread_ = NULL;

    setupUi(this);
    initUI();
    setAcceptDrops( true );

    connect( mAEADGroup, SIGNAL(clicked()), this, SLOT(clickUseAEAD()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(encDecInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(encDecUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(encDecFinal()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(dataChange()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mResetBtn, SIGNAL(clicked()), this, SLOT(clickReset()));

    connect( mEncryptRadio, SIGNAL(clicked()), this, SLOT(checkEncrypt()));
    connect( mDecryptRadio, SIGNAL(clicked()), this, SLOT(checkDecrypt()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(ivChanged()));
    connect( mAADText, SIGNAL(textChanged(const QString&)), this, SLOT(aadChanged()));
    connect( mTagText, SIGNAL(textChanged(const QString&)), this, SLOT(tagChanged()));

    connect( mInputTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(inputChanged()));;

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mIVTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(ivChanged()));
    connect( mAADTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(aadChanged()));
    connect( mAlgCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(algChanged()));
    connect( mModeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(modeChanged()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mFindDstFileBtn, SIGNAL(clicked()), this, SLOT(clickFindDstFile()));

    clickUseAEAD();
    mEncryptRadio->click();
    mRunBtn->setDefault(true);
    mInputText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mInputClearBtn->setFixedWidth(34);
    mOutputClearBtn->setFixedWidth(34);

    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);
#endif

    initialize();
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

EncDecDlg::~EncDecDlg()
{
    if( ctx_ ) JS_PKI_encryptFree( &ctx_ );
    if( thread_ ) delete thread_;
}

void EncDecDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void EncDecDlg::dropEvent(QDropEvent *event)
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

void EncDecDlg::initUI()
{
    mInputTypeCombo->addItems( kDataTypeList );
    mIVTypeCombo->addItems( kDataTypeList );
    mKeyTypeCombo->addItems( kDataTypeList );
    mAADTypeCombo->addItems( kDataTypeList );
    mOutputTypeCombo->addItems( kDataTypeList );

    mTagText->setPlaceholderText( tr("Hex value") );

    mAlgCombo->addItems( kSymAlgList );
    mAlgCombo->addItem( JS_PKI_KEY_NAME_CHACHA20  );

    mReqTagLenText->setText( "16" );

    mKeyText->setPlaceholderText( tr( "Select KeyList key" ));
    mSrcFileText->setPlaceholderText( tr( "Find the target file" ));

    mPadCheck->setChecked(true);
    mRunThreadCheck->setChecked(true);
}

void EncDecDlg::initialize()
{
    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mEncryptRadio );
    runGroup->addButton( mDecryptRadio );

    mInputTab->setCurrentIndex(0);
}

void EncDecDlg::showEvent( QShowEvent *event )
{

}

void EncDecDlg::Run()
{
    int index = mInputTab->currentIndex();

    if( index == 0 )
        dataRun();
    else
    {
        if( mAEADGroup->isChecked() == true )
        {
            if( isCCM( mModeCombo->currentText() ) == true )
            {
                QString strSrcFile = mSrcFileText->text();
                QFileInfo fileInfo( strSrcFile );
                mCCMDataLenText->setText( QString( "%1" ).arg( fileInfo.size() ));
            }
        }

        if( mRunThreadCheck->isChecked() )
            fileRunThread();
        else
            fileRun();
    }
}

void EncDecDlg::dataRun()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binIV = {0,0};
    BIN binKey = {0,0};
    BIN binOut = {0,0};
    BIN binAAD = {0,0};
    BIN binTag = {0,0};

    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    QString strInputType = mInputTypeCombo->currentText();

    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    qint64 us = 0;
    QElapsedTimer timer;

    QString strMethod;
    QString strOut;
    QString strSymAlg;

    bool bPad = mPadCheck->isChecked();


    mOutputText->clear();

    if( strInput.isEmpty() )
    {

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
                mKeyTypeCombo->setCurrentText( kDataHex );
                mKeyText->setText( strKey );
            }

            if( strIV.length() > 0 )
            {
                mIVTypeCombo->setCurrentText( kDataHex );
                mIVText->setText( strIV );
            }
        }

        if( strKey.isEmpty() )
        {
            berApplet->warningBox( tr( "Please enter key value" ), this );
            mKeyText->setFocus();
            return;
        }
    }

    if( strMode != JS_PKI_SYM_MODE_ECB )
    {
        if( strIV.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a IV" ), this );
            mIVText->setFocus();
            return;
        }
    }

    ret = getBINFromString( &binSrc, strInputType, strInput );
    FORMAT_WARN_GO(ret);

    ret = getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
    FORMAT_WARN_GO(ret);

    ret = getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
    FORMAT_WARN_GO(ret);

    ret = getSymAlg( strAlg, strMode, binKey.nLen, strSymAlg );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr("failed to get cipher name: %1" ).arg( JERR(ret)), this );
        goto end;
    }

    if( mAEADGroup->isChecked() )
    {
        int nReqTagLen = mReqTagLenText->text().toInt();
        QString strAAD = mAADText->text();

        ret = getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );
        FORMAT_WARN_GO(ret);

        if( mEncryptRadio->isChecked() )
        {
            char *pTag = NULL;
            strMethod = "AE Encrypt";

            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                timer.start();
                ret = JS_PKI_encryptChaCha20Poly1305( &binSrc, &binKey, &binIV, &binAAD, nReqTagLen, &binTag, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }
            else
            {
                if( isCCM(strMode) )
                {
                    timer.start();
                    ret = JS_PKI_encryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, nReqTagLen, &binTag, &binOut );
                    us = timer.nsecsElapsed() / 1000;
                }
                else
                {
                    timer.start();
                    ret = JS_PKI_encryptGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, nReqTagLen, &binTag, &binOut );
                    us = timer.nsecsElapsed() / 1000;
                }
            }

            JS_BIN_encodeHex( &binTag, &pTag );
            if( pTag )
            {
                mTagText->setText( pTag );
                JS_free( pTag );
            }

            if( binOut.nLen > 0 )
            {
                strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
                mOutputText->setPlainText( strOut );
            }

            if( ret == JSR_OK )
            {
                berApplet->logLine();
                berApplet->log( QString( "-- AE Encrypt [time: %1 ms]" ).arg( getMS( us )) );
                berApplet->logLine2();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Enc AAD    : %1" ).arg( getHexString( &binAAD )));
                berApplet->log( QString( "Enc Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();

                berApplet->messageLog( tr( "AE %1 success" ).arg( strSymAlg ), this );
            }
            else
            {
                berApplet->warnLog( tr( "AE %1 encryption error: %2").arg( strSymAlg ).arg( JERR(ret) ), this );
            }
        }
        else
        {
            QString strTag = mTagText->text();
            strMethod = "AE Decrypt";

            ret = getBINFromString( &binTag, DATA_HEX, strTag );
            FORMAT_WARN_GO(ret);

            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                timer.start();
                ret = JS_PKI_decryptChaCha20Poly1305( &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }
            else
            {
                if( isCCM( strMode ) )
                {
                    timer.start();
                    ret = JS_PKI_decryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
                    us = timer.nsecsElapsed() / 1000;
                }
                else
                {
                    timer.start();
                    ret = JS_PKI_decryptGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
                    us = timer.nsecsElapsed() / 1000;
                }
            }

            if( binOut.nLen > 0 )
            {
                strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
                mOutputText->setPlainText( strOut );
            }

            if( ret == JSR_OK )
            {
                berApplet->logLine();
                berApplet->log( QString( "-- AE Decrypt [time: %1 ms]" ).arg( getMS( us )) );
                berApplet->logLine2();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Dec AAD    : %1" ).arg( getHexString( &binAAD )));
                berApplet->log( QString( "Dec Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Dec Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();

                berApplet->messageLog( tr( "AD %1 success" ).arg( strSymAlg ), this );
            }
            else
            {
                berApplet->warnLog( tr( "AD %1 decryption error: %2").arg( strSymAlg ).arg( JERR(ret) ), this );
            }
        }
    }
    else
    {
        if( mEncryptRadio->isChecked() )
        {
            strMethod = "Encrypt";

            if( strAlg == JS_PKI_KEY_NAME_SEED )
            {
                timer.start();
                ret = JS_PKI_encryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }
            else
            {
                timer.start();
                ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }

            if( binOut.nLen > 0 )
            {
                strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
                mOutputText->setPlainText( strOut );
            }

            if( ret == JSR_OK )
            {
                berApplet->logLine();
                berApplet->log( QString( "-- Encrypt [time: %1 ms]" ).arg( getMS( us )) );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();

                berApplet->messageLog( tr( "%1 Encryption success" ).arg( strSymAlg ), this );
            }
            else
            {
                berApplet->warnLog( tr( "%1 Encryption error: %2").arg( strSymAlg ).arg( JERR(ret) ), this );
            }
        }
        else
        {
            strMethod = "Decrypt";

            if( strAlg == JS_PKI_KEY_NAME_SEED )
            {
                timer.start();
                ret = JS_PKI_decryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }
            else
            {
                timer.start();
                ret = JS_PKI_decryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
                us = timer.nsecsElapsed() / 1000;
            }

            if( binOut.nLen > 0 )
            {
                strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
                mOutputText->setPlainText( strOut );
            }

            if( ret == JSR_OK )
            {
                berApplet->logLine();
                berApplet->log( QString( "-- Decrypt [time: %1 ms]" ).arg( getMS( us ) ) );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Dec Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();

                berApplet->messageLog( tr( "%1 Decryption success" ).arg( strSymAlg ), this );
            }
            else
            {
                berApplet->warnLog( tr( "%1 Decryption error: %1").arg( strSymAlg ).arg( JERR(ret) ), this );
            }
        }
    }

    if( ret == 0 )
    {
        QString strMsg = QString( "%1 OK" ).arg( strMethod );
        mStatusLabel->setText( strMsg );
    }
    else
    {
        QString strMsg = QString("%1 %2 failed:%3").arg( strMethod ).arg( strSymAlg ).arg( JERR(ret) );
        mStatusLabel->setText( QString( "%1" ).arg(JERR(ret)) );
        berApplet->elog( strMsg );
    }

end :
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );

    update();
}

void EncDecDlg::fileRun()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nPercent = 0;
    int nUpdateCnt = 0;
    QString strSrcFile = mSrcFileText->text();
    BIN binPart = {0,0};
    BIN binDst = {0,0};

    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("Select a input file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mEncProgBar->setValue( 0 );
    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    nLeft = fileSize;
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();
    QString strDstFile = mDstFileText->text();
    if( strDstFile.length() < 1 )
    {
        QString strAppend;
        if( mEncryptRadio->isChecked() == true )
            strAppend = "enc";
        else
            strAppend = "dec";

        strDstFile = QString( "%1/%2_%3.bin" )
                         .arg( fileInfo.absolutePath() )
                         .arg( fileInfo.baseName() )
                         .arg( strAppend );

        mDstFileText->setText( strDstFile );
    }

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "The target file[%1] is already exist.\nDo you want to delete the file and continue?" ).arg( strDstFile );
        bool bVal = berApplet->yesOrNoBox( strMsg, this, false );

        if( bVal == true )
        {
            QFile::remove( strDstFile );
        }
        else
            return;
    }

    if( encDecInit() != 0 )
    {
        berApplet->elog( "Encryption/decryption initialization failure" );
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
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            berApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        if( mAEADGroup->isChecked() )
        {
            if( mEncryptRadio->isChecked() )
            {
                mOutputText->clear();

                if( isCCM(strMode) )
                    ret = JS_PKI_encryptCCMUpdate( ctx_, &binPart, &binDst );
                else
                    ret = JS_PKI_encryptGCMUpdate( ctx_, &binPart, &binDst );
            }
            else
            {
                if( isCCM(strMode))
                    ret = JS_PKI_decryptCCMUpdate( ctx_, &binPart, &binDst );
                else
                    ret = JS_PKI_decryptGCMUpdate( ctx_, &binPart, &binDst );
            }
        }
        else {
            if( mEncryptRadio->isChecked() )
            {
                mOutputText->clear();

                ret = JS_PKI_encryptUpdate( ctx_, &binPart, &binDst );
            }
            else
            {
                ret = JS_PKI_decryptUpdate( ctx_, &binPart, &binDst );
            }
        }

        if( ret != 0 )
        {
            berApplet->warnLog( tr( "Encryption/decryption update failed [%1]").arg(ret), this );
            mStatusLabel->setText( QString("%1").arg(JERR(ret)));
            mUpdateText->setText( QString("%1").arg(ret));
            goto end;
        }

        nUpdateCnt++;
        mStatusLabel->setText( "Update OK" );
        mUpdateText->setText( QString("%1").arg(nUpdateCnt));

        if( binDst.nLen > 0 )
        {
            ret = JS_BIN_fileAppend( &binDst, strDstFile.toLocal8Bit().toStdString().c_str() );
            if( ret != binDst.nLen )
            {
                berApplet->warnLog( tr( "fail to append file: %1" ).arg( ret ), this );
                goto end;
            }

            ret = 0;
        }

        nReadSize += nRead;
        nPercent = int( ( nReadSize * 100 ) / fileSize );

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mEncProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
        update();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mEncProgBar->setValue( 100 );

        if( ret == 0 )
        {
            QFileInfo fileInfo;
            fileInfo.setFile( strDstFile );
            qint64 fileSize = fileInfo.size();
            QDateTime cTime = fileInfo.lastModified();

            QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));
            mDstFileSizeText->setText( QString("%1").arg( fileSize ));
            mDstFileInfoText->setText( strInfo );

            ret = encDecFinal();
            if( ret == JSR_OK )
            {
                berApplet->messageLog( tr( "File(%1) save was successful" ).arg( strDstFile ), this );
            }
        }
    }

end :
    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binDst );
}

void EncDecDlg::clickUseAEAD()
{
    bool bStatus = mAEADGroup->isChecked();

    mAlgCombo->clear();
    mModeCombo->clear();

    if( bStatus )
    {
        mAlgCombo->addItems( kBaseSymList );
        mAlgCombo->addItem( JS_PKI_KEY_NAME_CHACHA20_POLY1305 );
        mModeCombo->addItems( modeAEList );
    }
    else
    {
        mAlgCombo->addItems( kSymAlgList );
        mAlgCombo->addItem( JS_PKI_KEY_NAME_CHACHA20 );
        mModeCombo->addItems( modeList );
    }
}

int EncDecDlg::encDecInit()
{
    int ret = -1;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binAAD = {0,0};
    BIN binTag = {0,0};
    int nDataType = DATA_STRING;

    QString strKey = mKeyText->text();
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    QString strReqTagLen = mReqTagLenText->text();
    QString strTag = mTagText->text();
    QString strIV = mIVText->text();

    clickReset();

    if( strAlg == JS_PKI_KEY_NAME_SEED )
    {
        QString strMode = mRunBtn->text();
        berApplet->warningBox(tr( "%1 does not support this feature[Init-Update-Final]\nUse %2")
                                  .arg( strAlg ).arg( strMode ), this );
        return JSR_UNSUPPORTED_ALGORITHM;
    }

    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));
        keyList.setManage(false);

        if( keyList.exec() == QDialog::Accepted )
        {
            strKey = keyList.getKey();

            if( strKey.length() > 0 )
            {
                mKeyTypeCombo->setCurrentText( kDataHex );
                mKeyText->setText( strKey );
            }

            if( keyList.getIV().length() > 0 )
            {
                strIV = keyList.getIV();
                mIVTypeCombo->setCurrentText( kDataHex );
                mIVText->setText( strIV );
            }
        }

        if( strKey.isEmpty() )
        {
            berApplet->warningBox( tr( "Please enter a key value" ), this );
            mKeyText->setFocus();
            return -1;
        }
    }

    if( strMode != "ECB" )
    {
        if( strIV.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a IV" ), this );
            mIVText->setFocus();
            return -1;
        }
    }


    mOutputText->clear();

    QString strInput = mInputText->toPlainText();
    QString strInputType = mInputTypeCombo->currentText();
    bool bPad = mPadCheck->isChecked();
    QString strSymAlg;

    ret = getBINFromString( &binSrc, strInputType, strInput );
    FORMAT_WARN_GO(ret);
    ret = getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
    FORMAT_WARN_GO(ret);
    ret = getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
    FORMAT_WARN_GO(ret);


    ret = getSymAlg( strAlg, strMode, binKey.nLen, strSymAlg );

    if( ret != JSR_OK )
    {
        berApplet->warningBox( tr( "failed to get cipher name: %1").arg( JERR(ret)), this );
        goto end;
    }

    if( mAEADGroup->isChecked() )
    {
        QString strAAD = mAADText->text();
        qint64 nDataLen = 0;

        ret = getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );
        FORMAT_WARN_GO(ret);

        if( strAlg != JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
        {
            if( isCCM( strMode ) )
            {
                nDataLen = mCCMDataLenText->text().toLongLong();
                if( nDataLen <= 0 )
                {
                    if( binSrc.nLen > 0 )
                    {
                        QString strMsg = tr( "Do you want the entire length of the data to be the length of the input value(%1)?" ).arg(binSrc.nLen);

                        bool bVal = berApplet->yesOrNoBox( strMsg, this );
                        if( bVal == false )
                        {
                            berApplet->warningBox( tr( "Enter the data length"), this );
                            mCCMDataLenText->setFocus();
                            goto end;
                        }

                        nDataLen = binSrc.nLen;
                        mCCMDataLenText->setText( QString("%1").arg( nDataLen ));
                    }
                    else
                    {
                        berApplet->warningBox( tr( "Enter the data length"), this );
                        mCCMDataLenText->setFocus();
                        goto end;
                    }
                }
            }
        }

        if( mEncryptRadio->isChecked() )
        {
            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_encryptChaCha20Poly1305Init( &ctx_, &binIV, &binKey, &binAAD );
            }
            else
            {
                if( isCCM( strMode) )
                {
                    int nReqTagLen = 0;

                    if( strReqTagLen.length() < 1 )
                    {
                        berApplet->warnLog( tr("Please enter request tag length" ), this );
                        goto end;
                    }

                    nReqTagLen = strReqTagLen.toInt();

                    ret = JS_PKI_encryptCCMInit( &ctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, &binAAD, nReqTagLen, nDataLen );
                }
                else
                {
                    ret = JS_PKI_encryptGCMInit( &ctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
                }
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Encrypt Init" );
                berApplet->log( QString( "SymAlg  : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Key : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV  : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Enc AAD : %1" ).arg( getHexString( &binAAD )));
            }
        }
        else
        {
            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_decryptChaCha20Poly1305Init( &ctx_, &binIV, &binKey, &binAAD );
            }
            else
            {
                if( isCCM( strMode ) )
                {
                    if( strTag.length() < 1 )
                    {
                        berApplet->warnLog( tr( "Please enter tag"), this );
                        ret = -1;
                        goto end;
                    }

                    JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );
                    ret = JS_PKI_decryptCCMInit( &ctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, &binAAD, &binTag, nDataLen );
                }
                else
                    ret = JS_PKI_decryptGCMInit( &ctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, &binAAD );
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Decrypt Init" );
                berApplet->log( QString( "SymAlg  : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Key : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV  : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Dec AAD : %1" ).arg( getHexString( &binAAD )));
            }
        }
    }
    else {
        if( mEncryptRadio->isChecked() )
        {
            ret = JS_PKI_encryptInit( &ctx_, strSymAlg.toStdString().c_str(), bPad, &binIV, &binKey );

            if( ret == 0 )
            {
                berApplet->log( "-- Encrypt Init" );
                berApplet->log( QString( "SymAlg  : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Key : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV  : %1" ).arg( getHexString( &binIV )));
            }
        }
        else
        {
            ret = JS_PKI_decryptInit( &ctx_, strSymAlg.toStdString().c_str(), bPad, &binIV, &binKey );

            if( ret == 0 )
            {
                berApplet->log( "-- Decrypt Init" );
                berApplet->log( QString( "SymAlg  : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Key : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV  : %1" ).arg( getHexString( &binIV )));
            }
        }
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );
        mInitText->setText( "OK" );
        mOutputText->clear();
    }
    else
    {
        QString strFail = QString("Init Error: %1").arg(JERR(ret));
        mStatusLabel->setText( QString("%1").arg( JERR(ret)) );
        mInitText->setText( QString("%1").arg(ret));
        berApplet->elog( strFail );
    }

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binTag );

    update();
    return ret;
}

int EncDecDlg::encDecUpdate()
{
    int ret = -1;
    BIN binSrc = {0,0};
    BIN binDst = {0,0};
    BIN binOut = {0,0};
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    QString strInputType = mInputTypeCombo->currentText();
    QString strOut = mOutputText->toPlainText();
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    if( strInput.isEmpty() )
    {

    }

    ret = getBINFromString( &binSrc, strInputType, strInput );
    FORMAT_WARN_GO(ret);

    if( strOut.length() > 0 )
    {
        ret = getBINFromString( &binOut, mOutputTypeCombo->currentText(), strOut );
        FORMAT_WARN_GO(ret);
    }

    if( mAEADGroup->isChecked() )
    {
        if( mEncryptRadio->isChecked() )
        {
            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_encryptChaCha20Poly1305Update( ctx_, &binSrc, &binDst );
            }
            else
            {
                if( isCCM(strMode) )
                    ret = JS_PKI_encryptCCMUpdate( ctx_, &binSrc, &binDst );
                else
                    ret = JS_PKI_encryptGCMUpdate( ctx_, &binSrc, &binDst );
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Encrypt Update" );
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Output : %1" ).arg( getHexString( &binDst )));
            }
        }
        else
        {
            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_decryptChaCha20Poly1305Update( ctx_, &binSrc, &binDst );
            }
            else
            {
                if( isCCM(strMode))
                    ret = JS_PKI_decryptCCMUpdate( ctx_, &binSrc, &binDst );
                else
                    ret = JS_PKI_decryptGCMUpdate( ctx_, &binSrc, &binDst );
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Decrypt Update" );
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Output : %1" ).arg( getHexString( &binDst )));
            }
        }


    }
    else {
        if( mEncryptRadio->isChecked() )
        {
            ret = JS_PKI_encryptUpdate( ctx_, &binSrc, &binDst );

            if( ret == 0 )
            {
                berApplet->log( "-- Encrypt Update");
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Output : %1" ).arg( getHexString( &binDst )));
            }
        }
        else
        {
            ret = JS_PKI_decryptUpdate( ctx_, &binSrc, &binDst );

            if( ret == 0 )
            {
                berApplet->log( "-- Decrypt Update");
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Output : %1" ).arg( getHexString( &binDst )));
            }
        }


    }

    if( ret == 0 )
    {
        int nUpdate = mUpdateText->text().toInt();
        if( nUpdate >= 0 )
        {
            nUpdate++;
            mUpdateText->setText( QString("%1").arg(nUpdate));
        }
        mStatusLabel->setText( "Update OK" );
        JS_BIN_appendBin( &binOut, &binDst );

        QString strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
        mOutputText->setPlainText( strOut );
    }
    else
    {
        QString strFail = QString("Update error: %1").arg(JERR(ret));
        mStatusLabel->setText( QString("%1").arg( JERR(ret) ) );
        berApplet->elog( strFail );
    }

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binOut );

    update();
    return ret;
}

int EncDecDlg::encDecFinal()
{
    int ret = -1;
    BIN binOut = {0,0};
    BIN binDst = {0,0};
    BIN binTag = {0,0};

    QString strOut = mOutputText->toPlainText();
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    if( mInputTab->currentIndex() == 0 && strOut.length() > 0 )
    {
        ret = getBINFromString( &binOut, mOutputTypeCombo->currentText(), strOut );
        FORMAT_WARN_GO(ret);
    }

    if( mAEADGroup->isChecked() )
    {
        int nReqTagLen = mReqTagLenText->text().toInt();

        if( mEncryptRadio->isChecked() )
        {
            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_encryptChaCha20Poly1305Final( ctx_, &binDst, nReqTagLen, &binTag );
            }
            else
            {
                if( isCCM(strMode) )
                    ret = JS_PKI_encryptCCMFinal( ctx_, &binDst, nReqTagLen, &binTag );
                else
                    ret = JS_PKI_encryptGCMFinal( ctx_, &binDst, nReqTagLen, &binTag );
            }

            if( binTag.nLen > 0 )
            {
                char *pTag = NULL;
                JS_BIN_encodeHex( &binTag, &pTag );
                if( pTag )
                {
                    mTagText->setText( pTag );
                    JS_free( pTag );
                }
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Encrypt Final" );
                berApplet->log( QString( "ReqTagLen  : %1").arg( nReqTagLen ));
                berApplet->log( QString( "Enc Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binDst )));
            }
        }
        else
        {
            QString strTag = mTagText->text();
            ret = getBINFromString( &binTag, DATA_HEX, strTag );
            FORMAT_WARN_GO(ret);

            if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
            {
                ret = JS_PKI_decryptChaCha20Poly1305Final( ctx_, &binTag, &binDst );
            }
            else
            {
                if( isCCM(strMode) )
                    ret = JS_PKI_decryptCCMFinal( ctx_, &binDst );
                else
                    ret = JS_PKI_decryptGCMFinal( ctx_, &binTag, &binDst );
            }

            if( ret == 0 )
            {
                berApplet->log( "-- AE Decrypt Final" );
                berApplet->log( QString( "Dec Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Final Output : %1" ).arg(getHexString( &binDst )));
            }
        }
    }
    else {
        if( mEncryptRadio->isChecked() )
        {
            ret = JS_PKI_encryptFinal( ctx_, &binDst );
            JS_PKI_encryptFree( &ctx_ );

            if( ret == 0 )
            {
                berApplet->log( "-- Encrypt Final" );
                berApplet->log( QString( "Enc Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binDst )));
            }

            berApplet->log( QString( "Final encryption result : %1" ).arg(getHexString( &binDst )));
        }
        else
        {
            ret = JS_PKI_decryptFinal( ctx_, &binDst );
            JS_PKI_decryptFree( &ctx_ );

            berApplet->log( QString( "Final decryption result : %1" ).arg(getHexString( &binDst )));

            if( ret == 0 )
            {
                berApplet->log( "-- Decrypt Final" );
                berApplet->log( QString( "Final Output : %1" ).arg(getHexString( &binDst )));
            }
        }
    }

    berApplet->log( QString( "final length : %1").arg( binDst.nLen ));

    if( binDst.nLen > 0 )
    {
        if( mInputTab->currentIndex() == 0 )
        {
            JS_BIN_appendBin( &binOut, &binDst );
            QString strLast = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
            mOutputText->setPlainText( strLast );
        }
        else
        {
            QString strDstPath = mDstFileText->text();
            JS_BIN_fileAppend( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
        }
    }

    if( ret == 0 )
    {
        mStatusLabel->setText( "Final OK" );
        mFinalText->setText( "OK" );
    }
    else
    {
        QString strFail = QString("Final error: %1").arg(JERR(ret));
        mStatusLabel->setText( QString("%1").arg( JERR(ret)));
        mFinalText->setText( QString("%1").arg(ret));
        berApplet->elog( strFail );
    }

end:
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binTag );

    return ret;
}

void EncDecDlg::clickReset()
{
    mStatusLabel->setText( "Status" );
    mInitText->clear();
    mUpdateText->clear();
    mFinalText->clear();

    if( ctx_ )
    {
        JS_PKI_encryptFree( &ctx_ );
        ctx_ = NULL;
    }
}

void EncDecDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();
    QString strOutputType = mOutputTypeCombo->currentText();

    mInputTypeCombo->setCurrentText( strOutputType );

    mOutputText->clear();
    mInputText->setPlainText( strOutput );
}

bool EncDecDlg::isCCM( const QString strMode )
{
    if( strMode.toUpper() == JS_PKI_SYM_MODE_CCM )
        return true;

    return false;
}

void EncDecDlg::inputChanged()
{    
    QString strType = mInputTypeCombo->currentText();

    QString strLen = getDataLenString( strType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::outputChanged()
{
    QString strLen = getDataLenString( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::keyChanged()
{
    QString strLen = getDataLenString( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::ivChanged()
{
    QString strLen = getDataLenString( mIVTypeCombo->currentText(), mIVText->text() );
    mIVLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::algChanged()
{
    QString strAlg = mAlgCombo->currentText();

    if( strAlg == JS_PKI_KEY_NAME_CHACHA20 || strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
    {
        mModeCombo->setEnabled( false );
        mPadCheck->setEnabled( false );
    }
    else
    {
        mModeCombo->setEnabled( true );
        mPadCheck->setEnabled( true );
    }

    modeChanged();
}

void EncDecDlg::aadChanged()
{
    QString strLen = getDataLenString( mAADTypeCombo->currentText(), mAADText->text() );
    mAADLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::tagChanged()
{
    QString strLen = getDataLenString( DATA_HEX, mTagText->text() );
    mTagLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::modeChanged()
{
    QString strMode = mModeCombo->currentText();
    QString strAlg = mAlgCombo->currentText();

    if( strMode.toUpper() == JS_PKI_SYM_MODE_CCM )
    {
        mCCMDataLenLabel->setEnabled( true );
        mCCMDataLenText->setEnabled( true );
    }
    else
    {
        mCCMDataLenLabel->setEnabled( false );
        mCCMDataLenText->setEnabled( false );
    }

    if( strMode == JS_PKI_SYM_MODE_ECB || strMode == JS_PKI_SYM_MODE_CBC )
        mPadCheck->setEnabled( true );
    else
        mPadCheck->setEnabled( false );

    if( strAlg == JS_PKI_KEY_NAME_CHACHA20 || strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
    {
        if( strAlg == JS_PKI_KEY_NAME_CHACHA20_POLY1305 )
        {
            mIVLabel->setText( tr("IV length is 12 bytes" ));
        }
        else
        {
            mIVLabel->setText( tr("If IV is less than 16 bytes in %1, the rest are set to 0").arg( strAlg ) );
        }
    }
    else
    {
        if( strMode == "ECB" )
        {
            mIVLabel->setText( tr("No IV required in %1").arg( strMode ) );
        }
        else if( strMode == "CBC" || strMode == "CTR" || strMode == "OFB" || strMode == "CFB" )
        {
            mIVLabel->setText( tr("If IV is less than 16 bytes in %1, the rest are set to 0").arg( strMode) );
        }
        else if( strMode == "GCM" )
        {
            mIVLabel->setText( tr( "IV length is arbitrary in %1" ).arg( strMode ));
        }
        else if( strMode == "CCM" )
        {
            mIVLabel->setText( tr( "IV length ranges from 7 to 13 bytes in %1" ).arg( strMode ));
        }
    }
}

void EncDecDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mAADText->clear();
    mIVText->clear();
    mKeyText->clear();
    mTagText->clear();
    mStatusLabel->setText( tr("Status" ));

    mSrcFileText->clear();
    mSrcFileInfoText->clear();
    mSrcFileSizeText->clear();
    mFileReadSizeText->clear();
    mFileTotalSizeText->clear();
    mDstFileText->clear();
    mEncProgBar->setValue(0);
}

void EncDecDlg::clickInputClear()
{
    mInputText->clear();
}

void EncDecDlg::clickOutputClear()
{
    mOutputText->clear();
}

void EncDecDlg::setSrcFileInfo( const QString strFile )
{
    if( strFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strFile );
        QString strMode;

        if( mEncryptRadio->isChecked() == true )
            strMode = "enc";
        else
            strMode = "dec";

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mEncProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void EncDecDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();

    QString strSrcFile = berApplet->findFile( this, JS_FILE_TYPE_ALL, strPath );
    setSrcFileInfo( strSrcFile );
}

void EncDecDlg::clickFindDstFile()
{
    int nType = JS_FILE_TYPE_BIN;
    QString strPath = mDstFileText->text();

    QString fileName = berApplet->findSaveFile( this, nType, strPath );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

void EncDecDlg::checkEncrypt()
{
    mHeadLabel->setText( tr( "Symmetric Encryption" ));

    mInputLabel->setText( tr("Source data") );
    mOutputLabel->setText( tr("Encrypted data" ) );

    mRunBtn->setText( tr("Encrypt" ) );
    mAEADLabel->setText( tr( "Authenticated Encryption" ));
}

void EncDecDlg::checkDecrypt()
{
    mHeadLabel->setText( tr( "Symmetric Decryption" ));

    mInputLabel->setText( tr("Encrypted data") );
    mOutputLabel->setText( tr("Decrypted data" ) );

    mRunBtn->setText( tr("Decrypt" ));
    mAEADLabel->setText( tr( "Authenticated Decryption" ));
}

void EncDecDlg::fileRunThread()
{
    if( encDecInit() != 0 )
    {
        berApplet->elog( "Encryption/decryption initialization failure" );
        return;
    }

    startTask();
}

void EncDecDlg::startTask()
{
    if( thread_ != nullptr ) delete thread_;

    thread_ = new EncDecThread;
    QString strSrcFile = mSrcFileText->text();
    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    if( strSrcFile.length() < 1)
    {
        berApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QString strDstFile = mDstFileText->text();
    if( strDstFile.length() < 1 )
    {
        QString strAppend;
        if( mEncryptRadio->isChecked() == true )
            strAppend = "enc";
        else
            strAppend = "dec";

        strDstFile = QString( "%1/%2_%3.bin" )
                         .arg( fileInfo.absolutePath() )
                         .arg( fileInfo.baseName() )
                         .arg( strAppend );

        mDstFileText->setText( strDstFile );
    }

    if( QFile::exists( strDstFile ) )
    {
        QString strMsg = tr( "The target file[%1] is already exist.\nDo you want to delete the file and continue?" ).arg( strDstFile );
        bool bVal = berApplet->yesOrNoBox( strMsg, this, false );

        if( bVal == true )
        {
            QFile::remove( strDstFile );
        }
        else
            return;
    }

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect( thread_, &EncDecThread::taskFinished, this, &EncDecDlg::onTaskFinished);
    connect( thread_, &EncDecThread::taskUpdate, this, &EncDecDlg::onTaskUpdate);

    thread_->setCTX( ctx_ );

    thread_->setMethod( mEncryptRadio->isChecked() ? false : true );
    thread_->setMode( mModeCombo->currentText() );
    thread_->setSrcFile( strSrcFile );
    thread_->setDstFile( strDstFile );
    thread_->start();

    berApplet->log("Task is running...");
}

void EncDecDlg::onTaskFinished()
{
    int ret = 0;
    berApplet->log("Task finished");
    QString strDstFile = mDstFileText->text();

    ret = encDecFinal();

    QFileInfo fileInfo;
    fileInfo.setFile( strDstFile );
    qint64 fileSize = fileInfo.size();
    QDateTime cTime = fileInfo.lastModified();

    QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));
    mDstFileSizeText->setText( QString("%1").arg( fileSize ));
    mDstFileInfoText->setText( strInfo );

    if( ret == 0 )
    {
        berApplet->messageLog( tr( "File(%1) save was successful" ).arg( strDstFile ), this );
    }

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void EncDecDlg::onTaskUpdate( qint64 nUpdate )
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

#ifdef QT_DEBUG
//    berApplet->elog( QString( "== Update: %1 Filesize: %2 Percent: %3" ).arg( nUpdate ).arg(nFileSize).arg(nPercent));
#endif

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mEncProgBar->setValue( nPercent );
}
