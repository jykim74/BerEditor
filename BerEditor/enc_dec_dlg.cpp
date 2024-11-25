/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileInfo>
#include <QDateTime>
#include <QFileDialog>
#include <QButtonGroup>

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
#include "js_pkcs11.h"
#include "p11api.h"

static QStringList dataTypes = {
    "String",
    "Hex",
    "Base64"
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
    is_hsm_ = false;

    setupUi(this);
    initialize();

    connect( mAEADGroup, SIGNAL(clicked()), this, SLOT(clickUseAEAD()));
    connect( mInitBtn, SIGNAL(clicked()), this, SLOT(encDecInit()));
    connect( mUpdateBtn, SIGNAL(clicked()), this, SLOT(encDecUpdate()));
    connect( mFinalBtn, SIGNAL(clicked()), this, SLOT(encDecFinal()));
    connect( mChangeBtn, SIGNAL(clicked()), this, SLOT(dataChange()));
    connect( mRunBtn, SIGNAL(clicked()), this, SLOT(Run()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mEncryptRadio, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mDecryptRadio, SIGNAL(clicked()), this, SLOT(clickDecrypt()));

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

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    connect( mInputClearBtn, SIGNAL(clicked()), this, SLOT(clickInputClear()));
    connect( mOutputClearBtn, SIGNAL(clicked()), this, SLOT(clickOutputClear()));
    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));
    connect( mFindDstFileBtn, SIGNAL(clicked()), this, SLOT(clickFindDstFile()));

    clickUseAEAD();
    mEncryptRadio->click();
    mRunBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
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

    mAlgCombo->addItems( algList );

    QButtonGroup *runGroup = new QButtonGroup;
    runGroup->addButton( mEncryptRadio );
    runGroup->addButton( mDecryptRadio );

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
    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    mOutputText->clear();

    if( strInput.isEmpty() )
    {

    }

    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strData = keyList.getData();
            QStringList keyIV = strData.split(":");

            if( keyIV.size() > 0 )
            {
                mKeyTypeCombo->setCurrentText( "Hex" );
                strKey = keyIV.at(0);
                mKeyText->setText( strKey );
            }

            if( keyIV.size() > 1 )
            {
                mIVTypeCombo->setCurrentText( "Hex" );
                strIV = keyIV.at(1);
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

    if( strMode != "ECB" )
    {
        if( strIV.length() < 1 )
        {
            berApplet->warningBox( tr( "Please enter a IV" ), this );
            mIVText->setFocus();
            return;
        }
    }

    QString strMethod;
    char *pOut = NULL;

    if( strKey.contains( "HSM:" ) == true )
    {
        ret = hsmEncDec();
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

        getBINFromString( &binSrc, nDataType, strInput );
        getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );

        if( binKey.nLen < 16 )
        {
            berApplet->warningBox( tr( "Key length(%1) is incorrect" ).arg( binKey.nLen), this );
            JS_BIN_reset( &binSrc );
            JS_BIN_reset( &binKey );
            mKeyText->setFocus();
            return;
        }




        getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );

        bool bPad = mPadCheck->isChecked();



        QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

        if( strSymAlg.isEmpty() || strSymAlg.isNull() )
        {
            berApplet->elog( QString("There is no symmetric key algorithm" ));
            goto end;
        }

        if( mAEADGroup->isChecked() )
        {
            int nReqTagLen = mReqTagLenText->text().toInt();
            QString strAAD = mAADText->text();

            getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

            if( mEncryptRadio->isChecked() )
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
            else
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
            if( mEncryptRadio->isChecked() )
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
            else
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
    }

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

    update();
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
        berApplet->warningBox( tr( "Find destination file"), this );
        mDstFileText->setFocus();
        return;
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
            goto end;
        }

        nUpdateCnt++;

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
        nPercent = ( nReadSize * 100 ) / fileSize;

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
            QString strStatus = QString( "|Update X %1").arg( nUpdateCnt );
            appendStatusLabel( strStatus );

            ret = encDecFinal();
            if( ret == 0 )
            {
                berApplet->messageLog( tr( "File(%1) save was successful" ).arg( strDstFile ), this );
            }

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

void EncDecDlg::clickUseAEAD()
{
    bool bStatus = mAEADGroup->isChecked();

    mModeCombo->clear();

    if( bStatus )
    {
        mModeCombo->addItems( modeAEList );
    }
    else
    {
        mModeCombo->addItems( modeList );
    }

    mPadCheck->setEnabled( !bStatus );

    modeChanged();
}

int EncDecDlg::hsmEncDecInit()
{
    int ret = 0;
    BIN binID = {0,0};
    BIN binIV = {0,0};
    BIN binAAD = {0,0};
    BIN binSrc = {0,0};
    JP11_CTX *pCTX = berApplet->getP11CTX();
    int nIndex = berApplet->settingsMgr()->hsmIndex();

    int nSaveType = -1;
    long uKeyType = -1;
    QString strKind;
    QString strID;
    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    long hObj = -1;
    int nDataType = DATA_HEX;
    CK_MECHANISM sMech;
    CK_GCM_PARAMS_PTR gcmParam = NULL;
    CK_CCM_PARAMS_PTR ccmParam = NULL;

    QString strAAD = mAADText->text();
    int nReqLen = mReqTagLenText->text().toInt();
    QString strInput = mInputText->toPlainText();

    getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

    memset( &sMech, 0x00, sizeof(sMech));

    getHSMPath( strKey, nSaveType, uKeyType, strKind, strID );

    ret = getP11SessionLogin( pCTX, nIndex );
    if( ret != 0 ) goto end;

    JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );

    hObj = getHandleHSM( pCTX, CKO_SECRET_KEY, &binID );


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

    sMech.mechanism = getP11EncMech();

    if( sMech.mechanism == CKM_AES_GCM )
    {
        gcmParam = (CK_GCM_PARAMS *)JS_calloc( 1, sizeof(CK_GCM_PARAMS));

        gcmParam->ulIvLen = binIV.nLen;
        gcmParam->pIv = binIV.pVal;
        gcmParam->ulAADLen = binAAD.nLen;
        gcmParam->pAAD = binAAD.pVal;
        gcmParam->ulIvBits = binIV.nLen * 8;
        gcmParam->ulTagBits = nReqLen * 8;

        sMech.pParameter = gcmParam;
        sMech.ulParameterLen = sizeof(CK_GCM_PARAMS);
    }
    else if( sMech.mechanism == CKM_AES_CCM )
    {
        int nDataLen = mCCMDataLength->text().toInt();
        if( nDataLen <= 0 )
        {
            nDataLen = binSrc.nLen;
        }
        ccmParam->ulDataLen = nDataLen;
        ccmParam->pNonce = binIV.pVal;
        ccmParam->ulNonceLen = binIV.nLen;
        ccmParam->pAAD = binAAD.pVal;
        ccmParam->ulAADLen = binAAD.nLen;
        ccmParam->ulMACLen = nReqLen;

        sMech.pParameter = ccmParam;
        sMech.ulParameterLen = sizeof(CK_CCM_PARAMS);
    }
    else
    {
        if( binIV.nLen > 0 )
        {
            sMech.pParameter = binIV.pVal;
            sMech.ulParameterLen = binIV.nLen;
        }
    }

    if( mEncryptRadio->isChecked() == true )
        ret = JS_PKCS11_EncryptInit( pCTX, &sMech, hObj );
    else
        ret = JS_PKCS11_DecryptInit( pCTX, &sMech, hObj );

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binSrc );

    if( gcmParam ) JS_free( gcmParam );
    if( ccmParam ) JS_free( ccmParam );

    return ret;
}

int EncDecDlg::hsmEncDecUpdate()
{
    int ret = 0;
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    BIN binSrc = {0,0};
    BIN binOut = {0,0};
    CK_BYTE *pRes = NULL;
    CK_ULONG uResLen = -1;
    char *pOut = NULL;

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

    pRes = (CK_BYTE *)JS_malloc( binSrc.nLen + 32 );
    uResLen = binSrc.nLen + 32;

    if( mEncryptRadio->isChecked() == true )
        ret = JS_PKCS11_EncryptUpdate( berApplet->getP11CTX(), binSrc.pVal, binSrc.nLen, pRes, &uResLen );
    else
        ret = JS_PKCS11_DecryptUpdate( berApplet->getP11CTX(), binSrc.pVal, binSrc.nLen, pRes, &uResLen );

    if( ret == CKR_OK)
    {
        JS_BIN_set( &binOut, pRes, uResLen );

        if( mAEADGroup->isChecked() == true )
        {
            int nTagLen = mReqTagLenText->text().toInt();
            BIN binTag = {0,0};

            if( nTagLen > binOut.nLen )
            {
                ret = JSR_ERR;
                goto end;
            }

            JS_BIN_set( &binTag, &binOut.pVal[binOut.nLen-nTagLen], nTagLen );
            binOut.nLen = binOut.nLen - nTagLen;
            mTagText->setText( getHexString( &binTag));
            JS_BIN_reset( &binTag );
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

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
    if( pRes ) JS_free( pRes );
    if( pOut ) JS_free( pOut );

    return ret;
}

int EncDecDlg::hsmEncDecFinal()
{
    int ret = 0;
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    BIN binOut = {0,0};
    CK_BYTE *pRes = NULL;
    CK_ULONG uResLen = -1;
    char *pOut = NULL;


    pRes = (CK_BYTE *)JS_malloc( 32 );
    uResLen = 32;

    if( mEncryptRadio->isChecked() == true )
        ret = JS_PKCS11_EncryptFinal( berApplet->getP11CTX(), pRes, &uResLen );
    else
        ret = JS_PKCS11_DecryptFinal( berApplet->getP11CTX(), pRes, &uResLen );

    if( ret == CKR_OK) JS_BIN_set( &binOut, pRes, uResLen );

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

end :
    JS_BIN_reset( &binOut );
    if( pRes ) JS_free( pRes );
    if( pOut ) JS_free( pOut );

    return ret;
}

int EncDecDlg::hsmEncDec()
{
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();
    BIN binSrc = {0,0};
    BIN binOut = {0,0};
    CK_BYTE *pRes = NULL;
    CK_ULONG uResLen = -1;
    char *pOut = NULL;


    int ret = hsmEncDecInit();
    if( ret != CKR_OK ) return ret;

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

    pRes = (CK_BYTE *)JS_malloc( binSrc.nLen + 32 );
    uResLen = binSrc.nLen + 32;

    if( mEncryptRadio->isChecked() == true )
        ret = JS_PKCS11_Encrypt( berApplet->getP11CTX(), binSrc.pVal, binSrc.nLen, pRes, &uResLen );
    else
        ret = JS_PKCS11_Decrypt( berApplet->getP11CTX(), binSrc.pVal, binSrc.nLen, pRes, &uResLen );

    if( ret == CKR_OK) JS_BIN_set( &binOut, pRes, uResLen );

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

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binOut );
    if( pRes ) JS_free( pRes );
    if( pOut ) JS_free( pOut );

    return ret;
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
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();

    QString strReqTagLen = mReqTagLenText->text();
    QString strTag = mTagText->text();
    QString strIV = mIVText->text();


    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strData = keyList.getData();
            QStringList keyIV = strData.split(":");

            if( keyIV.size() > 0 )
            {
                mKeyTypeCombo->setCurrentText( "Hex" );
                strKey = keyIV.at(0);
                mKeyText->setText( strKey );
            }

            if( keyIV.size() > 1 )
            {
                mIVTypeCombo->setCurrentText( "Hex" );
                strIV = keyIV.at(1);
                mIVText->setText( strIV );
            }
        }

<<<<<<< HEAD
        berApplet->warningBox( tr( "Please enter a key value" ), this );
        mKeyText->setFocus();
        return -1;
=======
        if( strKey.isEmpty() )
        {
            berApplet->warningBox( tr( "Please enter a key value" ), this );
            mKeyText->setFocus();
            return -1;
        }
>>>>>>> master
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

    mOutputText->clear();

    if( strKey.contains( "HSM:") == true )
    {
        is_hsm_ = true;
        ret = hsmEncDecInit();
    }
    else
    {
        getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
        getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );

        bool bPad = mPadCheck->isChecked();
        QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

        if( binKey.nLen < 16 )
        {
            berApplet->warningBox( tr( "Key length(%1) is incorrect" ).arg( binKey.nLen), this );
            mKeyText->setFocus();
            ret = -1;
            goto end;
        }

        if( mAEADGroup->isChecked() )
        {
            QString strAAD = mAADText->text();

            getBINFromString( &binAAD, mAADTypeCombo->currentText(), strAAD );

            int nDataLen = mCCMDataLength->text().toInt();
            if( nDataLen <= 0 )
            {
                nDataLen = binSrc.nLen;
                mCCMDataLength->setText( QString("%1").arg( nDataLen ));
            }

            if( mEncryptRadio->isChecked() )
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

    if( strInput.isEmpty() )
    {

    }

    if( is_hsm_ == true )
    {
        ret = hsmEncDecUpdate();
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

        if( mAEADGroup->isChecked() )
        {
            if( mEncryptRadio->isChecked() )
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

    update();
    return ret;
}

int EncDecDlg::encDecFinal()
{
    int ret = -1;
    BIN binOut = {0,0};
    BIN binDst = {0,0};
    BIN binTag = {0,0};

    if( is_hsm_ == true )
    {
        ret = hsmEncDecFinal();
    }
    else
    {
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

        if( mAEADGroup->isChecked() )
        {
            int nReqTagLen = mReqTagLenText->text().toInt();

            if( mEncryptRadio->isChecked() )
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
    }

    if( ret == 0 )
        appendStatusLabel( "|Final OK" );
    else
    {
        QString strFail = QString("|Final failure [%1]").arg(ret);
        appendStatusLabel( strFail );
        berApplet->elog( strFail );
    }

    JS_BIN_reset( &binOut );
    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binTag );

    update();
    return ret;
}

void EncDecDlg::dataChange()
{
    QString strOutput = mOutputText->toPlainText();

    if( mOutputTypeCombo->currentIndex() == 0 )
        mInputStringRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 1 )
        mInputHexRadio->setChecked(true);
    else if( mOutputTypeCombo->currentIndex() == 2 )
        mInputBase64Radio->setChecked(true);

    mOutputText->clear();
    mInputText->setPlainText( strOutput );

    update();
}

bool EncDecDlg::isCCM( const QString strMode )
{
    if( strMode == "ccm" || strMode == "CCM" )
        return true;

    return false;
}

long EncDecDlg::getP11EncMech()
{
    QString strAlg = mAlgCombo->currentText();
    QString strMode = mModeCombo->currentText();
    bool bPad = mPadCheck->isChecked();

    if( strAlg == "AES" )
    {
        if( strMode == "ECB" )
            return CKM_AES_ECB;
        else if( strMode == "CBC" )
        {
            if( bPad == true )
                return CKM_AES_CBC_PAD;
            else {
                return CKM_AES_CBC;
            }
        }
        else if( strMode == "CTR" )
            return CKM_AES_CTR;
        else if( strMode == "CFB" )
            return CKM_AES_CFB128;
        else if( strMode == "OFB" )
            return CKM_AES_OFB;
        else if( strMode == "GCM" )
            return CKM_AES_GCM;
        else if( strMode == "CCM" )
            return CKM_AES_CCM;
    }
    else if( strAlg == "ARIA" )
    {
        if( strMode == "ECB" )
            return CKM_ARIA_ECB;
        else if( strMode == "CBC" )
        {
            if( bPad == true )
                return CKM_ARIA_CBC_PAD;
            else {
                return CKM_ARIA_CBC;
            }
        }
    }
    else if( strAlg == "SEED" )
    {
        if( strMode == "ECB" )
            return CKM_SEED_ECB;
        else if( strMode == "CBC" )
        {
            if( bPad == true )
                return CKM_SEED_CBC_PAD;
            else {
                return CKM_SEED_CBC;
            }
        }
    }
    else if( strAlg == "DES3" )
    {
        if( strMode == "ECB" )
            return CKM_DES3_ECB;
        else if( strMode == "CBC" )
        {
            if( bPad == true )
                return CKM_DES3_CBC_PAD;
            else {
                return CKM_DES3_CBC;
            }
        }
    }

    return -1;
}

void EncDecDlg::inputChanged()
{
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mInputText->toPlainText() );
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

void EncDecDlg::aadChanged()
{
    QString strLen = getDataLenString( mAADTypeCombo->currentText(), mAADText->text() );
    mAADLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::tagChanged()
{
    QString strLen = getDataLenString( mTagTypeCombo->currentText(), mTagText->text() );
    mTagLenText->setText( QString("%1").arg(strLen));
}

void EncDecDlg::modeChanged()
{
    QString strMode = mModeCombo->currentText();

    if( strMode.toUpper() == "CCM" )
        mCCMDataLength->setEnabled( true );
    else
        mCCMDataLength->setEnabled( false );
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
    strPath = berApplet->curFilePath( strPath );

    QString strSrcFile = findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strSrcFile.length() > 0 )
    {
        QFileInfo fileInfo;
        fileInfo.setFile( strSrcFile );
        QString strMode;

        if( mEncryptRadio->isChecked() == true )
            strMode = "enc";
        else
            strMode = "dec";

        qint64 fileSize = fileInfo.size();
        QDateTime cTime = fileInfo.lastModified();

        QString strInfo = QString("LastModified Time: %1").arg( cTime.toString( "yyyy-MM-dd HH:mm:ss" ));

        mSrcFileText->setText( strSrcFile );
        mSrcFileSizeText->setText( QString("%1").arg( fileSize ));
        mSrcFileInfoText->setText( strInfo );
        mEncProgBar->setValue(0);



        QString strDstName = QString( "%1/%2_%3.bin" ).arg( fileInfo.absolutePath() ).arg( fileInfo.baseName() ).arg( strMode );

        mDstFileText->setText( strDstName );

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
        mDstFileInfoText->clear();
        mDstFileSizeText->clear();
    }
}

void EncDecDlg::clickFindDstFile()
{
    int nType = JS_FILE_TYPE_BIN;
    QString strPath = mDstFileText->text();
    strPath = berApplet->curFilePath( strPath );

    QString fileName = findSaveFile( this, nType, strPath );

    if( fileName.length() > 0 ) mDstFileText->setText( fileName );
}

void EncDecDlg::clickEncrypt()
{
    mRunBtn->setText( tr("Encrypt" ) );
    mAEADLabel->setText( tr( "Authenticated Encryption" ));
}

void EncDecDlg::clickDecrypt()
{
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

    if( strSrcFile.length() < 1)
    {
        berApplet->warningBox( tr( "Find source file"), this );
        mSrcFileText->setFocus();
        return;
    }

    QString strDstFile = mDstFileText->text();
    if( strDstFile.length() < 1 )
    {
        berApplet->warningBox( tr( "Find destination file"), this );
        mDstFileText->setFocus();
        return;
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

    QFileInfo fileInfo;
    fileInfo.setFile( strSrcFile );

    qint64 fileSize = fileInfo.size();

    mFileTotalSizeText->setText( QString("%1").arg( fileSize ));
    mFileReadSizeText->setText( "0" );

    connect( thread_, &EncDecThread::taskFinished, this, &EncDecDlg::onTaskFinished);
    connect( thread_, &EncDecThread::taskUpdate, this, &EncDecDlg::onTaskUpdate);

    if( is_hsm_ == true )
        thread_->setCTX( true, berApplet->getP11CTX() );
    else
        thread_->setCTX( false, ctx_ );

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

    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    ret = encDecFinal();
    if( ret == 0 )
    {
        berApplet->messageLog( tr( "File(%1) save was successful" ).arg( strDstFile ), this );
    }

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
