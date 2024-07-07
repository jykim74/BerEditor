/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>

#include "enc_dec_dlg.h"
#include "ui_enc_dec_dlg.h"
#include "js_ber.h"
#include "js_bin.h"
#include "js_pki.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "enc_dec_thread.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
};

static QStringList methodTypes = {
    "Encrypt",
    "Decrypt"
};

static QStringList algList = {
    "AES",
    "ARIA",
    "DES3",
    "SEED",
    "SM4"
};

static QStringList modeList = {
  "ECB", "CBC", "CTR", "CFB", "OFB"
};

static QStringList modeAEList = {
    "GCM", "CCM"
};

EncDecDlg::EncDecDlg(QWidget *parent) :
    QDialog(parent)
{
    ctx_ = NULL;
    thread_ = NULL;
    update_cnt_ = 0;

    setupUi(this);
    initialize();

    connect( mUseAECheck, SIGNAL(clicked()), this, SLOT(clickUseAE()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(encDecInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(encDecUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(encDecFinal()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(dataChange()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mInputText, SIGNAL(textChanged()), this, SLOT(inputChanged()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(outputChanged()));
    connect( mKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(keyChanged()));
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(ivChanged()));
    connect( mAADText, SIGNAL(textChanged(const QString&)), this, SLOT(aadChanged()));
    connect( mTagText, SIGNAL(textChanged(const QString&)), this, SLOT(tagChanged()));

    connect( mInputStringRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputHexRadio, SIGNAL(clicked()), this, SLOT(inputChanged()));
    connect( mInputBase64Radio, SIGNAL(clicked()), this, SLOT(inputChanged()));

    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mIVTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(ivChanged()));
    connect( mAADTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(aadChanged()));
    connect( mTagTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(tagChanged()));
    connect( mModeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(modeChanged()));

    connect( mMethodCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeMethod(int)));
    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mFindDstFileBtn, SIGNAL(clicked()), this, SLOT(clickFindDstFile()));

    clickUseAE();
    mCloseBtn->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    tabFile->layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

EncDecDlg::~EncDecDlg()
{
    if( ctx_ ) JS_PKI_encryptFree( &ctx_ );
    if( thread_ ) delete thread_;
}

void EncDecDlg::initialize()
{
    mIVTypeCombo->addItems( dataTypes );
    mKeyTypeCombo->addItems( dataTypes );
    mAADTypeCombo->addItems( dataTypes );
    mTagTypeCombo->addItems( dataTypes );
    mOutputTypeCombo->addItems( dataTypes );
    mOutputTypeCombo->setCurrentIndex(1);

    mMethodCombo->addItems( methodTypes );
    mAlgCombo->addItems( algList );

    mReqTagLenText->setText( "16" );
    mInputTab->setCurrentIndex(0);
}

void EncDecDlg::appendStatusLabel( const QString& strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
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
    mOutputText->clear();

    if( strInput.isEmpty() )
    {

    }

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

    getBINFromString( &binSrc, nDataType, strInput );

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter key value" ), this );
        JS_BIN_reset(&binSrc);
        return;
    }

    getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );

    if( binKey.nLen < 16 )
    {
        berApplet->warningBox( tr( "Key length(%1) is incorrect" ).arg( binKey.nLen), this );
        JS_BIN_reset( &binSrc );
        JS_BIN_reset( &binKey );
        return;
    }

    QString strIV = mIVText->text();
    QString strMethod;

    getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );

    bool bPad = mPadCheck->isChecked();

    char *pOut = NULL;
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();
    QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

    if( strSymAlg.isEmpty() || strSymAlg.isNull() )
    {
        berApplet->elog( QString("There is no symmetric key algorithm" ));
        goto end;
    }

    if( mUseAECheck->isChecked() )
    {
        int nReqTagLen = mReqTagLenText->text().toInt();
        QString strAAD = mAADText->text();

        getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            char *pTag = NULL;
            strMethod = "AE Encrypt";

            if( isCCM(strMode) )
                ret = JS_PKI_encryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, nReqTagLen, &binTag, &binOut );
            else
                ret = JS_PKI_encryptGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, nReqTagLen, &binTag, &binOut );

            mTagTypeCombo->setCurrentIndex( DATA_HEX );
            JS_BIN_encodeHex( &binTag, &pTag );
            if( pTag )
            {
                mTagText->setText( pTag );
                JS_free( pTag );
            }

            if( ret == 0 )
            {
                berApplet->logLine();
                berApplet->log( "-- AE Encrypt" );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Enc AAD    : %1" ).arg( getHexString( &binAAD )));
                berApplet->log( QString( "Enc Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();
            }
        }
        else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
        {
            QString strTag = mTagText->text();
            strMethod = "AE Decrypt";

            getBINFromString( &binTag, mTagTypeCombo->currentText(), strTag );

            if( isCCM( strMode ) )
                ret = JS_PKI_decryptCCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );
            else
                ret = JS_PKI_decryptGCM( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binAAD, &binTag, &binOut );

            if( ret == 0 )
            {
                berApplet->logLine();
                berApplet->log("-- AE Decrypt" );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Dec AAD    : %1" ).arg( getHexString( &binAAD )));
                berApplet->log( QString( "Dec Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Dec Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();
            }
        }
    }
    else
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            strMethod = "Encrypt";

            if( strAlg == "SEED" )
                ret = JS_PKI_encryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
            else
                ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );

            if( ret == 0 )
            {
                berApplet->logLine();
                berApplet->log( "-- Encrypt" );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Enc IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Enc Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();
            }
        }
        else if( mMethodCombo->currentIndex() == ENC_DECRYPT )
        {
            strMethod = "Decrypt";

            if( strAlg == "SEED" )
                ret = JS_PKI_decryptSEED( strMode.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );
            else
                ret = JS_PKI_decryptData( strSymAlg.toStdString().c_str(), bPad, &binSrc, &binIV, &binKey, &binOut );

            if( ret == 0 )
            {
                berApplet->logLine();
                berApplet->log( "-- Decrypt" );
                berApplet->logLine();
                berApplet->log( QString( "SymAlg     : %1").arg( strSymAlg ));
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Key    : %1" ).arg( getHexString( &binKey )));
                berApplet->log( QString( "Dec IV     : %1" ).arg( getHexString( &binIV )));
                berApplet->log( QString( "Dec Output : %1" ).arg(getHexString( &binOut )));
                berApplet->logLine();
            }
        }
    }

    if( mOutputTypeCombo->currentIndex() == DATA_STRING )
    {
        JS_BIN_string( &binOut, &pOut );
    }
    else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
    {
        JS_BIN_encodeHex( &binOut, &pOut );
    }
    else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
    {
        JS_BIN_encodeBase64( &binOut, &pOut );
    }

    mOutputText->setPlainText( pOut );

    if( ret == 0 )
    {
        update_cnt_++;
        QString strMsg = QString( "%1 OK" ).arg( strMethod );
        mStatusLabel->setText( strMsg );
    }
    else
    {
        QString strMsg = QString("%1 failed:%2").arg( strMethod ).arg( ret );
        mStatusLabel->setText( strMsg );
        berApplet->elog( strMsg );
    }

end :
    if( pOut ) JS_free(pOut);
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );

    repaint();
}

void EncDecDlg::fileRun()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
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
        if( nRead <= 0 ) break;

        if( mUseAECheck->isChecked() )
        {
            if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
            if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
            berApplet->elog( QString( "Encryption/decryption update failed [%1]").arg(ret));
            break;
        }

        nUpdateCnt++;

        if( binDst.nLen > 0 )
            JS_BIN_fileAppend( &binDst, strDstFile.toLocal8Bit().toStdString().c_str() );

        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

        mFileReadSizeText->setText( QString("%1").arg( nReadSize ));
        mEncProgBar->setValue( nPercent );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
        repaint();
    }

    fclose( fp );
    berApplet->log( QString("FileRead done[Total:%1 Read:%2]").arg( fileSize ).arg( nReadSize) );

    if( nReadSize == fileSize )
    {
        mEncProgBar->setValue( 100 );

        if( ret == 0 )
        {
            QString strStatus = QString( "|Update X %1").arg( nUpdateCnt );
            appendStatusLabel( strStatus );

            encDecFinal();

            QFileInfo fileInfo;
            fileInfo.setFile( strDstFile );
            qint64 fileSize = fileInfo.size();
            QDateTime cTime = fileInfo.lastModified();

            QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));
            mDstFileSizeText->setText( QString("%1").arg( fileSize ));
            mDstFileInfoText->setText( strInfo );
        }
    }

end :
    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binDst );
}

void EncDecDlg::clickUseAE()
{
    bool bStatus = mUseAECheck->isChecked();

    mModeCombo->clear();

    if( bStatus )
    {
        mModeCombo->addItems( modeAEList );
    }
    else
    {
        mModeCombo->addItems( modeList );
    }

    mAADText->setEnabled( bStatus );
    mAADTypeCombo->setEnabled( bStatus );
    mTagText->setEnabled( bStatus );
    mTagTypeCombo->setEnabled( bStatus );
    mCCMDataLength->setEnabled( bStatus );
    mReqTagLenText->setEnabled( bStatus );

    mPadCheck->setEnabled( !bStatus );

    modeChanged();
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

    if( ctx_ )
    {
        JS_PKI_encryptFree( &ctx_ );
        ctx_ = NULL;
    }

    update_cnt_ = 0;

    QString strKey = mKeyText->text();

    if( strKey.isEmpty() )
    {
        berApplet->warningBox( tr( "Please enter a key value" ), this );
        return -1;
    }

    mOutputText->clear();

    QString strInput = mInputText->toPlainText();

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

    getBINFromString( &binSrc, nDataType, strInput );
    getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );

    QString strIV = mIVText->text();

    getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );

    bool bPad = mPadCheck->isChecked();

    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();
    QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );
    QString strReqTagLen = mReqTagLenText->text();
    QString strTag = mTagText->text();



    if( binKey.nLen < 16 )
    {
        berApplet->warningBox( tr( "Key length(%1) is incorrect" ).arg( binKey.nLen), this );
        ret = -1;
        goto end;
    }

    if( mUseAECheck->isChecked() )
    {
        QString strAAD = mAADText->text();

        getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

        int nDataLen = mCCMDataLength->text().toInt();
        if( nDataLen <= 0 )
        {
            nDataLen = binSrc.nLen;
            mCCMDataLength->setText( QString("%1").arg( nDataLen ));
        }

        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
        mStatusLabel->setText( "Initialization successful" );
        mOutputText->clear();
    }
    else
    {
        QString strFail = QString("Initialization failed [%1]").arg(ret);
        mStatusLabel->setText( strFail );
        berApplet->elog( strFail );
    }

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binTag );

    repaint();
    return ret;
}

void EncDecDlg::encDecUpdate()
{
    int ret = -1;
    BIN binSrc = {0,0};
    BIN binDst = {0,0};
    BIN binOut = {0,0};
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();

    if( strInput.isEmpty() )
    {

    }

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

    getBINFromString( &binSrc, nDataType, strInput );

    QString strOut = mOutputText->toPlainText();

    if( strOut.length() > 0 )
    {
        if( mOutputTypeCombo->currentIndex() == DATA_STRING )
            JS_BIN_set( &binOut, (unsigned char *)strOut.toStdString().c_str(), strOut.length() );
        else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
            JS_BIN_decodeHex( strOut.toStdString().c_str(), &binOut );
        else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
            JS_BIN_decodeBase64( strOut.toStdString().c_str(), &binOut );
    }

    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    if( mUseAECheck->isChecked() )
    {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( isCCM(strMode) )
                ret = JS_PKI_encryptCCMUpdate( ctx_, &binSrc, &binDst );
            else
                ret = JS_PKI_encryptGCMUpdate( ctx_, &binSrc, &binDst );

            if( ret == 0 )
            {
                berApplet->log( "-- AE Encrypt Update" );
                berApplet->log( QString( "Enc Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Enc Output : %1" ).arg( getHexString( &binDst )));
            }
        }
        else
        {
            if( isCCM(strMode))
                ret = JS_PKI_decryptCCMUpdate( ctx_, &binSrc, &binDst );
            else
                ret = JS_PKI_decryptGCMUpdate( ctx_, &binSrc, &binDst );

            if( ret == 0 )
            {
                berApplet->log( "-- AE Decrypt Update" );
                berApplet->log( QString( "Dec Src    : %1" ).arg( getHexString( &binSrc )));
                berApplet->log( QString( "Dec Output : %1" ).arg( getHexString( &binDst )));
            }
        }


    }
    else {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
        JS_BIN_appendBin( &binOut, &binDst );

        QString strOut = getStringFromBIN( &binOut, mOutputTypeCombo->currentText() );
        mOutputText->setPlainText( strOut );

        appendStatusLabel( "|Update OK" );
    }
    else
    {
        QString strFail = QString("Update failed [%1]").arg(ret);
        mStatusLabel->setText( strFail );
        berApplet->elog( strFail );
    }

    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binOut );

    repaint();
}

void EncDecDlg::encDecFinal()
{
    int ret = -1;
    BIN binOut = {0,0};
    BIN binDst = {0,0};
    BIN binTag = {0,0};

    QString strOut = mOutputText->toPlainText();

    if( mInputTab->currentIndex() == 0 && strOut.length() > 0 )
    {
        if( mOutputTypeCombo->currentIndex() == DATA_STRING )
            JS_BIN_set( &binOut, (unsigned char *)strOut.toStdString().c_str(), strOut.length() );
        else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
            JS_BIN_decodeHex( strOut.toStdString().c_str(), &binOut );
        else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
            JS_BIN_decodeBase64( strOut.toStdString().c_str(), &binOut );
    }

    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    if( mUseAECheck->isChecked() )
    {
        int nReqTagLen = mReqTagLenText->text().toInt();

        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
        {
            if( isCCM(strMode) )
                ret = JS_PKI_encryptCCMFinal( ctx_, &binDst, nReqTagLen, &binTag );
            else
                ret = JS_PKI_encryptGCMFinal( ctx_, &binDst, nReqTagLen, &binTag );

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

            if( mTagTypeCombo->currentIndex() == DATA_STRING )
                JS_BIN_set( &binTag, (unsigned char *)strTag.toStdString().c_str(), strTag.length() );
            else if( mTagTypeCombo->currentIndex() == DATA_HEX )
                JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );
            else if( mTagTypeCombo->currentIndex() == DATA_BASE64 )
                JS_BIN_decodeBase64( strTag.toStdString().c_str(), &binTag );

            if( isCCM(strMode) )
                ret = JS_PKI_decryptCCMFinal( ctx_, &binDst );
            else
                ret = JS_PKI_decryptGCMFinal( ctx_, &binTag, &binDst );

            if( ret == 0 )
            {
                berApplet->log( "-- AE Decrypt Final" );
                berApplet->log( QString( "Dec Tag    : %1" ).arg( getHexString( &binTag )));
                berApplet->log( QString( "Final Output : %1" ).arg(getHexString( &binDst )));
            }
        }
    }
    else {
        if( mMethodCombo->currentIndex() == ENC_ENCRYPT )
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
            char *pOut = NULL;

            if( mOutputTypeCombo->currentIndex() == DATA_STRING )
            {
                JS_BIN_string( &binOut, &pOut );
            }
            else if( mOutputTypeCombo->currentIndex() == DATA_HEX )
            {
                JS_BIN_encodeHex( &binOut, &pOut );
            }
            else if( mOutputTypeCombo->currentIndex() == DATA_BASE64 )
            {
                JS_BIN_encodeBase64( &binOut, &pOut );
            }

            mOutputText->setPlainText( pOut );

            if( pOut ) JS_free(pOut);
        }
        else
        {
            QString strDstPath = mDstFileText->text();
            JS_BIN_fileAppend( &binDst, strDstPath.toLocal8Bit().toStdString().c_str() );
        }
    }

    if( ret == 0 )
        appendStatusLabel( "|Final OK" );
    else
    {
        QString strFail = QString("final failure [%1]").arg(ret);
        mStatusLabel->setText( strFail );
        berApplet->elog( strFail );
    }

    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binTag );

    repaint();
}

void EncDecDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();

    mInputText->setPlainText( strOutput );
    mOutputText->clear();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    repaint();
}

bool EncDecDlg::isCCM( const QString strMode )
{
    if( strMode == "ccm" || strMode == "CCM" )
        return true;

    return false;
}

void EncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    int nLen = getDataLen( nType, mInputText->toPlainText() );
    mInputLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::outputChanged()
{
    int nLen = getDataLen( mOutputTypeCombo->currentText(), mOutputText->toPlainText() );
    mOutputLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::keyChanged()
{
    int nLen = getDataLen( mKeyTypeCombo->currentText(), mKeyText->text() );
    mKeyLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::ivChanged()
{
    int nLen = getDataLen( mIVTypeCombo->currentText(), mIVText->text() );
    mIVLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::aadChanged()
{
    int nLen = getDataLen( mAADTypeCombo->currentText(), mAADText->text() );
    mAADLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::tagChanged()
{
    int nLen = getDataLen( mTagTypeCombo->currentText(), mTagText->text() );
    mTagLenText->setText( QString("%1").arg(nLen));
}

void EncDecDlg::modeChanged()
{
    QString strMode = mModeCombo->currentText();

    if( strMode.toUpper() == "CCM" )
        mCCMDataLength->setEnabled( true );
    else
        mCCMDataLength->setEnabled( false );
}

void EncDecDlg::changeMethod( int index )
{
    if( index == 0 )
        mRunBtn->setText( tr( "Encrypt" ));
    else
        mRunBtn->setText( tr( "Decrypt"));
}

void EncDecDlg::clickClearDataAll()
{
    mInputText->clear();
    mOutputText->clear();
    mAADText->clear();
    mIVText->clear();
    mKeyText->clear();
    mTagText->clear();
    mStatusLabel->clear();

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

void EncDecDlg::clickFindSrcFile()
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
        mEncProgBar->setValue(0);

        QStringList nameExt = strSrcFile.split(".");
        QString strDstName = QString( "%1.dst" ).arg( nameExt.at(0) );
        if( strSrcFile == strDstName )
        {
            strDstName += "_dst";
        }

        mDstFileText->setText( strDstName );

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void EncDecDlg::clickFindDstFile()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    QString strPath = mDstFileText->text();

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("encryption or decryption files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
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

    if( strSrcFile.length() < 1)
    {
        berApplet->warningBox( tr( "Find source file"), this );
        return;
    }

    QString strDstFile = mDstFileText->text();

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

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect( thread_, &EncDecThread::taskFinished, this, &EncDecDlg::onTaskFinished);
    connect( thread_, &EncDecThread::taskUpdate, this, &EncDecDlg::onTaskUpdate);

    thread_->setCTX( ctx_ );

    thread_->setMethod( mMethodCombo->currentIndex() == 0 ? false : true );
    thread_->setMode( mModeCombo->currentText() );
    thread_->setSrcFile( strSrcFile );
    thread_->setDstFile( strDstFile );
    thread_->start();

    berApplet->log("Task is running...");
}

void EncDecDlg::onTaskFinished()
{
    berApplet->log("Task finished");

    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    encDecFinal();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void EncDecDlg::onTaskUpdate( int nUpdate )
{
    berApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mEncProgBar->setValue( nPercent );
}
