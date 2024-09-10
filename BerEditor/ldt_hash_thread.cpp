#include "ldt_hash_thread.h"
#include "common.h"

LDTHashThread::LDTHashThread()
{
    is_stop_ = false;

    content_.clear();
    hash_.clear();
    full_length_bits_ = 0;
}

LDTHashThread::~LDTHashThread()
{

}

void LDTHashThread::setStop( bool bStop )
{
    is_stop_ = bStop;
}

void LDTHashThread::setContent( const QString strContent )
{
    content_ = strContent;
}

void LDTHashThread::setHash( const QString strHash )
{
    hash_ = strHash;
}

void LDTHashThread::setFullLengthBits( qint64 nLengthBits )
{
    full_length_bits_ = nLengthBits;
}

void LDTHashThread::makeLDT()
{
    int ret = 0;
    void *pCTX = NULL;

    BIN binContent = {0,0};
    BIN binMD = {0,0};
    qint64 nCurBits = 0;

    qint64 nUpdateCur = 0;
    qint64 nUpdateBlock = 0;

    if( content_.length() < 1 ) return;
    if( hash_.length() < 1 ) return;
    if( full_length_bits_ < 1 ) return;

    JS_BIN_decodeHex( content_.toStdString().c_str(), &binContent );

    if( binContent.nLen < 1 ) goto end;

    nUpdateBlock = full_length_bits_ / 1000;

    ret = JS_PKI_hashInit( &pCTX, hash_.toStdString().c_str() );
    if( ret != 0 ) goto end;

    while( nCurBits < full_length_bits_ )
    {
        if( is_stop_ == true ) goto end;

        ret = JS_PKI_hashUpdate( pCTX, &binContent );
        if( ret != 0 ) goto end;

        nCurBits += (binContent.nLen * 8);
        nUpdateCur += (binContent.nLen * 8);

        if( nUpdateCur > nUpdateBlock )
        {
            emit taskUpdate( nCurBits );
            nUpdateCur = 0;
        }
    }

    emit taskUpdate( nCurBits );
    ret = JS_PKI_hashFinal( pCTX, &binMD );
    if( ret != 0 ) goto end;

    emit taskLastUpdate( getHexString( &binMD ));

end :
    JS_BIN_reset( &binContent );
    JS_BIN_reset( &binMD );
    if( pCTX ) JS_PKI_hashFree( &pCTX );

    emit taskFinished( ret );

    return;
}

void LDTHashThread::run()
{
    makeLDT();
}
