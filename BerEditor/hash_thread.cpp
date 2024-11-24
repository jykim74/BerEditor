#include "hash_thread.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "common.h"
#include "js_pkcs11.h"
#include "p11api.h"


#include <QFileInfo>
#include <QTextCursor>

HashThread::HashThread()
{
    pctx_ = NULL;
}

HashThread::~HashThread()
{
    pctx_ = NULL;
}

void HashThread::setCTX( bool bHSM, void *pCTX )
{
    is_hsm_ = bHSM;

    pctx_ = pCTX;
}


void HashThread::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void HashThread::run()
{
    int ret = 0;
    int nRead = 0;
    int nPartSize = berApplet->settingsMgr()->fileReadSize();
    int nReadSize = 0;
    int nLeft = 0;
    int nOffset = 0;
    int nUpdateCnt = 0;

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

        if( is_hsm_ == true )
        {
            ret = JS_PKCS11_DigestUpdate( (JP11_CTX *)pctx_, (CK_BYTE_PTR)binPart.pVal, binPart.nLen );
        }
        else
            ret = JS_PKI_hashUpdate( pctx_, &binPart );

        if( ret != 0 )
        {
            berApplet->elog( QString( "failed to update : %1").arg(ret));
            break;
        }

        nUpdateCnt++;
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
