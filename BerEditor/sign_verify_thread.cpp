#include "sign_verify_thread.h"
#include "mac_thread.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "common.h"
#include "gen_mac_dlg.h"

#include <QFileInfo>

SignVerifyThread::SignVerifyThread()
{
    sctx_ = NULL;
    is_verify_ = false;
    is_hsm_ = false;
}

SignVerifyThread::~SignVerifyThread()
{
    sctx_ = NULL;
    is_verify_ = false;
}

void SignVerifyThread::setSignCTX( bool bHSM, void *pCTX )
{
    is_hsm_ = bHSM;
    sctx_ = pCTX;
}

void SignVerifyThread::setVerify( bool bVerify )
{
    is_verify_ = bVerify;
}

void SignVerifyThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void SignVerifyThread::run()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;

    BIN binPart = {0,0};
    QFileInfo fileInfo;
    fileInfo.setFile( src_file_ );

    qint64 fileSize = fileInfo.size();

    FILE *fp = fopen( src_file_.toLocal8Bit().toStdString().c_str(), "rb" );
    if( fp == NULL )
    {
        fprintf( stderr, "failed to read file:%s\n", src_file_.toStdString().c_str());
        goto end;
    }

    nLeft = fileSize;

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

        if( is_verify_ == false )
        {
            if( is_hsm_ == true )
                ret = JS_PKCS11_SignUpdate( (JP11_CTX *)sctx_, binPart.pVal, binPart.nLen );
            else
                ret = JS_PKI_signUpdate( sctx_, &binPart );
        }
        else
        {
            ret = JS_PKI_verifyUpdate( sctx_, &binPart );
        }

        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update [%1]").arg(ret));
            break;
        }

        nReadSize += nRead;
        emit taskUpdate( nReadSize );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
    }

    fclose( fp );

end :
    if( nReadSize == fileSize )
    {
        emit taskFinished();
    }

    JS_BIN_reset( &binPart );
}
