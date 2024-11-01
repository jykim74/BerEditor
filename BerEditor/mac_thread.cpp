#include "mac_thread.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "common.h"
#include "gen_mac_dlg.h"

#include <QFileInfo>

MacThread::MacThread()
{
    hctx_ = NULL;
}

MacThread::~MacThread()
{
    hctx_ = NULL;
}

void MacThread::setCTX( void *pCTX )
{
    hctx_ = pCTX;
}

void MacThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

int MacThread::setType( int nType )
{
    type_ = nType;
}

void MacThread::run()
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

        if( type_ == JS_TYPE_CMAC )
        {
            ret = JS_PKI_cmacUpdate( hctx_, &binPart );
        }
        else if( type_ == JS_TYPE_HMAC )
        {
            ret = JS_PKI_hmacUpdate( hctx_, &binPart );
        }
        else if( type_ == JS_TYPE_GMAC )
        {
            ret = JS_PKI_encryptGCMUpdateAAD( hctx_, &binPart );
        }

        if( ret != 0 )
        {
            fprintf( stderr, "failed to update : %d\n", ret);
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
