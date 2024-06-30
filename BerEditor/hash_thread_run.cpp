#include "hash_thread_run.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pki.h"

#include <QFileInfo>

HashThreadRun::HashThreadRun()
{
    pctx_ = NULL;
}

HashThreadRun::~HashThreadRun()
{
    pctx_ = NULL;
}

void HashThreadRun::setCTX( void *pCTX )
{
    pctx_ = pCTX;
}

void HashThreadRun::setSrcFile( const QString strSrcFile )
{
    src_file_ = strSrcFile;
}

void HashThreadRun::run()
{
    /*
    for( int i =0; i < 100; i++ )
    {
        QThread::sleep(1);
        emit taskUpdate(i);
    }
    */
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
        berApplet->elog( QString( "failed to read file:%1").arg( src_file_ ));
        goto end;
    }

    nLeft = fileSize;

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

        nUpdateCnt++;
        nReadSize += nRead;

        emit taskUpdate( nReadSize );

        nLeft -= nPartSize;
        nOffset += nRead;

        JS_BIN_reset( &binPart );
    }

    fclose( fp );

    if( nReadSize == fileSize )
    {
        emit taskUpdate(fileSize);
    }

end :
    emit taskFinished();
    JS_BIN_reset( &binPart );
}
