#include "enc_dec_thread.h"
#include "mac_thread.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "common.h"
#include "gen_mac_dlg.h"

#include <QFileInfo>

static bool isCCM( const QString strMode )
{
    if( strMode == "ccm" || strMode == "CCM" )
        return true;

    return false;
}

EncDecThread::EncDecThread()
{
    ctx_ = NULL;
    is_ae_ = false;
    is_dec_ = false;
    src_file_.clear();
    dst_file_.clear();
}

EncDecThread::~EncDecThread()
{
    ctx_ = NULL;
    is_ae_ = false;
    is_dec_ = false;
    src_file_.clear();
    dst_file_.clear();
}

void EncDecThread::setCTX( void *pCTX )
{
    ctx_ = pCTX;
}

void EncDecThread::setAE( bool bAE )
{
    is_ae_ = bAE;
}

void EncDecThread::setMethod( bool bDec )
{
    is_dec_ = bDec;
}

void EncDecThread::setMode( const QString strMode )
{
    mode_ = strMode;
}

void EncDecThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void EncDecThread::setDstFile( const QString strDstFile )
{
    dst_file_ = strDstFile;
}

void EncDecThread::run()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    qint64 nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    BIN binPart = {0,0};
    BIN binDst = {0,0};


    QFileInfo fileInfo;
    fileInfo.setFile( src_file_ );

    qint64 fileSize = fileInfo.size();

    nLeft = fileSize;

    FILE *fp = fopen( src_file_.toLocal8Bit().toStdString().c_str(), "rb" );
    if( fp == NULL )
    {
        fprintf( stderr, "failed to read file:%s\n", src_file_.toStdString().c_str());
        goto end;
    }

    while( nLeft > 0 )
    {
        if( nLeft < nPartSize )
            nPartSize = nLeft;

        nRead = JS_BIN_fileReadPartFP( fp, nOffset, nPartSize, &binPart );
        if( nRead <= 0 )
        {
            fprintf( stderr, "fail to read file: %d\n", nRead );
            goto end;
        }

        if( is_ae_ )
        {
            if( is_dec_ == false )
            {
                if( isCCM( mode_) )
                    ret = JS_PKI_encryptCCMUpdate( ctx_, &binPart, &binDst );
                else
                    ret = JS_PKI_encryptGCMUpdate( ctx_, &binPart, &binDst );
            }
            else
            {
                if( isCCM(mode_))
                    ret = JS_PKI_decryptCCMUpdate( ctx_, &binPart, &binDst );
                else
                    ret = JS_PKI_decryptGCMUpdate( ctx_, &binPart, &binDst );
            }
        }
        else {
            if( is_dec_ == false )
            {
                ret = JS_PKI_encryptUpdate( ctx_, &binPart, &binDst );
            }
            else
            {
                ret = JS_PKI_decryptUpdate( ctx_, &binPart, &binDst );
            }
        }

        if( ret != 0 )
        {
            fprintf( stderr, "Encryption/decryption update failed [%d]\n", ret );
            break;
        }

        if( binDst.nLen > 0 )
        {
            ret = JS_BIN_fileAppend( &binDst, dst_file_.toLocal8Bit().toStdString().c_str() );
            if( ret != binDst.nLen )
            {
                fprintf( stderr, "fail to append file: %d\n", ret );
                goto end;
            }

            ret = 0;
        }

        nReadSize += nRead;
        emit taskUpdate( nReadSize );


        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
        JS_BIN_reset( &binDst );
    }

    fclose( fp );

end :
    if( nReadSize == fileSize )
    {
        emit taskFinished();
    }

    JS_BIN_reset( &binPart );
    JS_BIN_reset( &binDst );
}
