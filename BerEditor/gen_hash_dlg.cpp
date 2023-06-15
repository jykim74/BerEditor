#include "gen_hash_dlg.h"
#include "ui_gen_hash_dlg.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_ber.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"

#include <QDialogButtonBox>
#include <QFileInfo>
#include <QDateTime>


GenHashDlg::GenHashDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    pctx_ = NULL;

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

    initialize();

    mCloseBtn->setFocus();
}

GenHashDlg::~GenHashDlg()
{
//    delete ui;
    if( pctx_ ) JS_PKI_hashFree( &pctx_ );
}

void GenHashDlg::initialize()
{
    SettingsMgr *setMgr = berApplet->settingsMgr();

    mOutputHashCombo->addItems( kHashList );
    mOutputHashCombo->setCurrentText( setMgr->defaultHash() );

    mInputTab->setCurrentIndex(0);
}

void GenHashDlg::hashInit()
{
    int ret = 0;

    if( pctx_ )
    {
        JS_PKI_hashFree( &pctx_ );
        pctx_ = NULL;
    }

    QString strAlg = mOutputHashCombo->currentText();

    ret = JS_PKI_hashInit( &pctx_, strAlg.toStdString().c_str() );
    if( ret == 0 )
    {
        mStatusLabel->setText( "Init OK" );

        berApplet->log( QString( "Init Algorithm : %1" ).arg( strAlg ));
    }
    else
        mStatusLabel->setText( QString("Init Fail:%1").arg(ret) );

    repaint();
}

void GenHashDlg::hashUpdate()
{
    int ret = 0;

    BIN binSrc = {0,0};

    QString inputStr = mInputText->toPlainText();

    if( inputStr.isEmpty() )
    {

    }
    else
    {
        if( mInputStringRadio->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)inputStr.toStdString().c_str(), inputStr.length() );
        else if( mInputHexRadio->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Radio->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( inputStr.toStdString().c_str(), &binSrc );
        }
    }

    ret = JS_PKI_hashUpdate( pctx_, &binSrc );
    if( ret == 0 )
    {
        berApplet->log( QString( "Update Src : %1" ).arg( getHexString(&binSrc)));
        mStatusLabel->setText( "Update OK" );
    }
    else
        mStatusLabel->setText( QString("Update fail:%1").arg(ret) );

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
        char *pHex = NULL;
        JS_BIN_encodeHex( &binMD, &pHex );
        mOutputText->setPlainText( pHex );
        mStatusLabel->setText( "Final OK" );
        JS_free( pHex );

        berApplet->log( QString("Final Digest : %1").arg( getHexString(&binMD)));
    }
    else
    {
        mStatusLabel->setText( QString("Final Fail:%1").arg(ret) );
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
        clickDigestSrcFile();
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
        if( mInputStringRadio->isChecked() )
            JS_BIN_set( &binSrc, (unsigned char *)inputStr.toStdString().c_str(), inputStr.length() );
        else if( mInputHexRadio->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeHex( inputStr.toStdString().c_str(), &binSrc );
        }
        else if( mInputBase64Radio->isChecked() )
        {
            inputStr.remove(QRegExp("[\t\r\n\\s]"));
            JS_BIN_decodeBase64( inputStr.toStdString().c_str(), &binSrc );
        }
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

        berApplet->log( QString( "Algorithm : %1" ).arg( strHash ));
        berApplet->log( QString( "Input     : %1" ).arg( getHexString( &binSrc) ));
        berApplet->log( QString( "Digest    : %1" ).arg(getHexString(&binHash)));
    }
    else
    {
        mStatusLabel->setText( QString("Digest Fail:%1").arg(ret) );
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
        mHashProgBar->setValue(0);
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
    BIN binMD = {0,0};


    if( strSrcFile.length() < 1 )
    {
        berApplet->warningBox( tr("You have to find src file"), this );
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

    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

//        nRead = JS_BIN_fileReadPart( strSrcFile.toLocal8Bit().toStdString().c_str(), nOffset, nPartSize, &binPart );
        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 ) break;

        ret = JS_PKI_hashUpdate( pctx_, &binPart );
        if( ret != 0 )
        {
            berApplet->elog( QString( "fail to update hash : %1").arg(ret));
            break;
        }

        nReadSize += nRead;
        nPercent = ( nReadSize * 100 ) / fileSize;

//        berApplet->log( QString( "ReadData: %1" ).arg( getHexString(binPart.pVal, binPart.nLen )));
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
            ret = JS_PKI_hashFinal( pctx_, &binMD );
            if( ret != 0 )
            {
                berApplet->elog( QString( "fail to finalize hash : %1").arg(ret));
                goto end;
            }

            QString strMsg = tr( "File Hash OK" );
            berApplet->log( QString( "file Hash: %1").arg( getHexString(binMD.pVal, binMD.nLen)));
            mOutputText->setPlainText( getHexString( binMD.pVal, binMD.nLen ));
            mStatusLabel->setText( strMsg );
            berApplet->messageBox( strMsg, this );
        }
    }

end :
    JS_PKI_hashFree( &pctx_ );
    pctx_ = NULL;
    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binMD );
}
