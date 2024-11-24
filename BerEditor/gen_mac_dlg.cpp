/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
#include "mac_thread.h"
#include "js_error.h"
#include "key_list_dlg.h"
#include "save_device_dlg.h"
#include "p11api.h"


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
    thread_ = NULL;
    update_cnt_ = 0;
    is_hsm_ = false;

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
    connect( mIVText, SIGNAL(textChanged(const QString&)), this, SLOT(ivChanged()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyChanged()));
    connect( mHMACRadio, SIGNAL(clicked()), this, SLOT(checkHMAC()));
    connect( mCMACRadio, SIGNAL(clicked()), this, SLOT(checkCMAC()));
    connect( mGMACRadio, SIGNAL(clicked()), this, SLOT(checkGMAC()));

    connect( mFindSrcFileBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcFile()));

    connect( mClearDataAllBtn, SIGNAL(clicked()), this, SLOT(clickClearDataAll()));

    initialize();
    mMACBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mDataTab->layout()->setSpacing(5);
    mDataTab->layout()->setMargin(5);
    mFileTab->layout()->setSpacing(5);
    mFileTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

GenMacDlg::~GenMacDlg()
{
    if( group_ ) delete group_;
    if( thread_ ) delete thread_;

    freeCTX();
}

void GenMacDlg::initialize()
{
    mKeyTypeCombo->addItems( keyTypes );
    mIVTypeCombo->addItems( keyTypes );

    group_->addButton( mHMACRadio );
    group_->addButton( mCMACRadio );
    group_->addButton( mGMACRadio );

    mInputTab->setCurrentIndex(0);

    checkHMAC();
}

void GenMacDlg::appendStatusLabel( const QString strLabel )
{
    QString strStatus = mStatusLabel->text();
    strStatus += strLabel;
    mStatusLabel->setText( strStatus );
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

long GenMacDlg::getP11Mech()
{
    QString strAlg = mAlgTypeCombo->currentText();

    if( mHMACRadio->isChecked() == true );
    {
        if( strAlg == "SHA1" )
            return CKM_SHA_1_HMAC;
        else if( strAlg == "SHA224" )
            return CKM_SHA224_HMAC;
        else if( strAlg == "SHA256" )
            return CKM_SHA256_HMAC;
        else if( strAlg == "SHA384" )
            return CKM_SHA384_HMAC;
        else if( strAlg == "SHA512" )
            return CKM_SHA512_HMAC;
        else if( strAlg == "MD5" )
            return CKM_MD5_HMAC;
    }

    if( mCMACRadio->isChecked() == true )
    {
        if( strAlg == "AES" )
            return CKM_AES_CMAC;
        else if( strAlg == "ARIA" )
            return CKM_ARIA_MAC;
        else if( strAlg == "3DES" )
            return CKM_DES3_CMAC;
    }

    if( mGMACRadio->isChecked() == true )
    {
        if( strAlg == "AES" )
            return CKM_AES_GMAC;
    }

    return -1;
}

int GenMacDlg::macInit()
{
    int ret = 0;
    update_cnt_ = 0;

    if( hctx_ )
    {
        freeCTX();
        hctx_ = NULL;
    }

    BIN binKey = {0,0};

    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    if( strKey.length() < 1 )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));

        keyList.mKeyTypeCombo->setCurrentText( "HMAC" );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strData = keyList.getData();
            QStringList keyIV = strData.split("#");

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

        if( strKey.length() < 1 )
        {
            berApplet->warningBox( tr("Enter a key value"), this );
            mKeyText->setFocus();
            return JSR_ERR;
        }
    }

    QString strAlg = mAlgTypeCombo->currentText();

    if( strKey.contains( "HSM:" ) == true )
    {
        ret = hsmMACInit( strKey, strIV );
    }
    else
    {
        getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );
        if( binKey.nLen <= 0 )
        {
            berApplet->warningBox( tr( "There is an invalid character"), this );
            mKeyText->setFocus();
            return JSR_ERR2;
        }

        mOutputText->clear();

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
            QString strIV = mIVText->text();

            getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );

            if( strIV.length() < 1 )
            {
                berApplet->warningBox( tr("Enter a IV value"), this );
                mIVText->setFocus();
                ret = JSR_ERR;
                goto end;
            }

            ret = JS_PKI_encryptGCMInit( &hctx_, strSymAlg.toStdString().c_str(), &binIV, &binKey, NULL );
            if( ret == 0 ) type_ = JS_TYPE_GMAC;
        }
    }

    berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
    berApplet->log( QString( "Key       : %1" ).arg( getHexString( &binKey )));

    if( ret == 0 )
    {
        mStatusLabel->setText( "Initialization successful" );
    }
    else
        mStatusLabel->setText( QString("Initialization failed [%1]").arg( ret ) );

end :
    JS_BIN_reset( &binKey );
    update();
    return ret;
}

void GenMacDlg::macUpdate()
{
    int ret = 0;
    BIN binSrc = {0,0};
    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
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
    }

    if( is_hsm_ == true )
    {
        ret = JS_PKCS11_SignUpdate( berApplet->getP11CTX(), binSrc.pVal, binSrc.nLen );
    }
    else
    {
        if( mCMACRadio->isChecked() )
        {
            if( type_ != JS_TYPE_CMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_cmacUpdate( hctx_, &binSrc );
        }
        else if( mHMACRadio->isChecked() )
        {
            if( type_ != JS_TYPE_HMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_hmacUpdate( hctx_, &binSrc );
        }
        else if( mGMACRadio->isChecked() )
        {
            if( type_ != JS_TYPE_GMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binSrc );
        }
    }

    berApplet->log( QString( "Update input : %1" ).arg( getHexString(&binSrc)));

    if( ret == 0 )
    {
        appendStatusLabel( "|Update OK" );
    }
    else
        mStatusLabel->setText( QString("Update failure [%1]").arg(ret) );

    JS_BIN_reset( &binSrc );
    update();
}

void GenMacDlg::macFinal()
{
    int ret = 0;
    BIN binMAC = {0,0};

    if( is_hsm_ == true )
    {
        CK_BYTE sSign[512];
        CK_ULONG uSignLen = 512;

        ret = JS_PKCS11_SignFinal( berApplet->getP11CTX(), sSign, &uSignLen );
        if( ret == CKR_OK ) JS_BIN_set( &binMAC, sSign, uSignLen );
    }
    else
    {
        if( mCMACRadio->isChecked() )
        {
            if( type_ != JS_TYPE_CMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_cmacFinal( hctx_, &binMAC );
        }
        else if( mHMACRadio->isChecked() )
        {
            if( type_ != JS_TYPE_HMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_hmacFinal( hctx_, &binMAC );
        }
        else if( mGMACRadio->isChecked() )
        {
            BIN binEnc = {0,0};
            if( type_ != JS_TYPE_GMAC )
            {
                berApplet->elog( "Invalid type" );
                return;
            }

            ret = JS_PKI_encryptGCMFinal( hctx_, &binEnc, 16, &binMAC );
            JS_BIN_reset( &binEnc );
        }
    }

    if( ret == 0 )
    {   
        mOutputText->setPlainText( getHexString( &binMAC) );
        appendStatusLabel( "|Final OK" );

        berApplet->log( QString( "Final Digest : %1" ).arg( getHexString( &binMAC )) );
    }
    else
        appendStatusLabel( QString("|Final failure [%1]").arg(ret) );

    freeCTX();

    JS_BIN_reset( &binMAC );

    update();
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

int GenMacDlg::hsmMACInit( const QString strKey, const QString strIV )
{
    int ret = 0;
    BIN binID = {0,0};
    BIN binIV = {0,0};
    JP11_CTX *pCTX = berApplet->getP11CTX();
    int nIndex = berApplet->settingsMgr()->hsmIndex();

    int nSaveType = -1;
    long uKeyType = -1;
    QString strID;

    long hObj = -1;
    CK_MECHANISM sMech;

    memset( &sMech, 0x00, sizeof(sMech));

    getDevicePath( strKey, nSaveType, strID, uKeyType );

    ret = getP11SessionLogin( pCTX, nIndex );
    if( ret != 0 ) goto end;

    JS_BIN_decodeHex( strID.toStdString().c_str(), &binID );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );

    hObj = getHandleHSM( pCTX, CKO_SECRET_KEY, &binID );

    sMech.mechanism = getP11Mech();
    if( binIV.nLen > 0 )
    {
        sMech.pParameter = binIV.pVal;
        sMech.ulParameterLen = binIV.nLen;
    }

    ret = JS_PKCS11_SignInit( pCTX, &sMech, hObj );

end :
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binIV );

    return ret;
}

void GenMacDlg::clickMAC()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binMAC = {0,0};
    BIN binIV = {0,0};

    int nDataType = DATA_STRING;

    QString strInput = mInputText->toPlainText();

    if( strInput.length() > 0 )
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
    }

    QString strKey = mKeyText->text();
    QString strIV = mIVText->text();

    if( strKey.isEmpty() )
    {
        KeyListDlg keyList;
        keyList.setTitle( tr( "Select symmetric key" ));

        keyList.mKeyTypeCombo->setCurrentText( "HMAC" );

        if( keyList.exec() == QDialog::Accepted )
        {
            QString strData = keyList.getData();
            QStringList keyIV = strData.split("#");

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
            berApplet->warningBox( tr( "Please Enter a key value"), this );
            JS_BIN_reset(&binSrc);
            mKeyText->setFocus();
            return;
        }
    }

    QString strAlg = mAlgTypeCombo->currentText();

    if( strKey.contains( "HSM:" ) == true )
    {
        ret = hsmMACInit( strKey, strIV );
    }
    else
    {
        getBINFromString( &binKey, mKeyTypeCombo->currentText(), strKey );

        if( mCMACRadio->isChecked() )
        {
            QString strSymAlg = getSymAlg( strAlg, "CBC", binKey.nLen );
            ret = JS_PKI_genCMAC( strSymAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
        }
        else if( mHMACRadio->isChecked() )
        {
            ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binMAC );
        }
        else if( mGMACRadio->isChecked() )
        {
            QString strIV = mIVText->text();
            getBINFromString( &binIV, mIVTypeCombo->currentText(), strIV );
            if( strIV.length() < 1 )
            {
                 berApplet->warningBox( tr("Enter a IV value"), this );
                 mIVText->setFocus();
                 ret = JSR_ERR;
                 goto end;
            }

            ret = JS_PKI_genGMAC( strAlg.toStdString().c_str(), &binSrc, &binKey, &binIV, &binMAC );
        }
    }

    if( ret == 0 )
    {
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMAC, &pHex );
        mOutputText->setPlainText( pHex );
        mStatusLabel->setText( "MAC success" );
        if( pHex ) JS_free(pHex);

        berApplet->logLine();
        berApplet->log( "-- MAC" );
        berApplet->logLine();
        berApplet->log( QString( "Algorithm : %1" ).arg( strAlg ));
        berApplet->log( QString( "Input : %1" ).arg(getHexString(&binSrc)));
        berApplet->log( QString( "Key   : %1" ).arg( getHexString(&binKey)));
        berApplet->log( QString( "MAC   : %1" ).arg( getHexString(&binMAC)));
        berApplet->logLine();
    }
    else
    {
        mStatusLabel->setText( QString("MAC failure [%1]").arg(ret) );
    }

end :
    JS_BIN_reset(&binSrc);
    JS_BIN_reset(&binKey);
    JS_BIN_reset(&binMAC);
    JS_BIN_reset(&binIV);

    update();
}

void GenMacDlg::clickFindSrcFile()
{
    QString strPath = mSrcFileText->text();
    strPath = berApplet->curFilePath( strPath );

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
        mMACProgBar->setValue(0);

        mFileReadSizeText->clear();
        mFileTotalSizeText->clear();
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
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            berApplet->warnLog( tr( "fail to read file: %1").arg( nRead ), this );
            goto end;
        }

        if( is_hsm_ == true )
        {
            ret = JS_PKCS11_SignUpdate( berApplet->getP11CTX(), binPart.pVal, binPart.nLen );
        }
        else
        {
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
        }

        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update : %1").arg(ret));
            break;
        }

        update_cnt_++;
        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

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
            QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
            appendStatusLabel( strStatus );

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
    int nType = DATA_STRING;

    if( mInputHexRadio->isChecked() )
        nType = DATA_HEX;
    else if( mInputBase64Radio->isChecked() )
        nType = DATA_BASE64;

    QString strLen = getDataLenString( nType, mInputText->toPlainText() );
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

void GenMacDlg::checkHMAC()
{
    bool bVal = false;

    mIVLabel->setEnabled(bVal);
    mIVTypeCombo->setEnabled(bVal);
    mIVText->setEnabled(bVal);
    mIVLenText->setEnabled(bVal );

    mHMACRadio->setChecked(true);

    mAlgTypeCombo->clear();

    mAlgTypeCombo->addItems( kHashList );
    mAlgTypeCombo->setCurrentText( berApplet->settingsMgr()->defaultHash() );
}

void GenMacDlg::checkCMAC()
{
    bool bVal = false;

    mIVLabel->setEnabled(bVal);
    mIVTypeCombo->setEnabled(bVal);
    mIVText->setEnabled(bVal);
    mIVLenText->setEnabled(bVal );

    mCMACRadio->setChecked(true);

    mAlgTypeCombo->clear();
    mAlgTypeCombo->addItems( cryptList );
}

void GenMacDlg::checkGMAC()
{
    bool bVal = true;

    mIVLabel->setEnabled(bVal);
    mIVTypeCombo->setEnabled(bVal);
    mIVText->setEnabled(bVal);
    mIVLenText->setEnabled(bVal );

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
    thread_->setCTX( is_hsm_, hctx_ );
    thread_->setSrcFile( strSrcFile );
    thread_->start();

    berApplet->log("Task is running...");
}

void GenMacDlg::onTaskFinished()
{
    berApplet->log("Task finished");

    QString strStatus = QString( "|Update X %1").arg( update_cnt_ );
    appendStatusLabel( strStatus );

    macFinal();
    freeCTX();

    thread_->quit();
    thread_->wait();
    thread_->deleteLater();
    thread_ = nullptr;
}

void GenMacDlg::onTaskUpdate( int nUpdate )
{
    berApplet->log( QString("Update: %1").arg( nUpdate ));
    int nFileSize = mFileTotalSizeText->text().toInt();
    int nPercent = (nUpdate * 100) / nFileSize;
    update_cnt_++;

    mFileReadSizeText->setText( QString("%1").arg( nUpdate ));
    mMACProgBar->setValue( nPercent );
}
