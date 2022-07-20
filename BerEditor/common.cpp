#include <QString>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>

#include "common.h"
#include "js_pki_tools.h"

QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

//    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strType = QObject::tr("BER Files (*.ber *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_CFG )
        strType = QObject::tr("Config Files (*.cfg *.ini);;All Files(*.*)" );
    else if( nType == JS_FILE_TYPE_REQ )
        strType = QObject::tr("Req Files (*.req *.txt);;All Files(*.*)" );

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};

QString findFolder( QWidget *parent, const QString strPath )
{
    QFileDialog::Options options;
    options |= QFileDialog::ShowDirsOnly;
    options |= QFileDialog::DontResolveSymlinks;


    QString folderName = QFileDialog::getExistingDirectory(
                parent, QObject::tr("Open Directory"), strPath, options);

    return folderName;
}

int setOIDList( const QString& strOIDPath )
{
    int ret = 0;
    int nCount = 0;


    QString strOID;
    QString strSN;
    QString strLN;

    QFile file( strOIDPath );

    if( !file.open(QIODevice::ReadOnly | QIODevice::Text))
        return -1;

    QTextStream in( &file );
    QString line = in.readLine();

    while( 1 )
    {
        QString strName;
        QString strVal;

        if( line.length() == 0 || line.isNull() )
        {
            if( strOID.length() > 0 && strSN.length() > 0 )
            {
                if( strLN.length() < 1 ) strLN = strSN;
                ret = JS_PKI_createOID( strOID.toStdString().c_str(), strSN.toStdString().c_str(), strLN.toStdString().c_str() );
                if( ret > 0 ) nCount++;
            }

            strOID.clear();
            strSN.clear();
            strLN.clear();

            if( line.isNull() ) break;

            line = in.readLine();
            continue;
        }

        if( line.at(0) == '#' )
        {
            line = in.readLine();
            continue;
        }

        QStringList nameVal = line.split( "=" );
        if( nameVal.size() != 2 )
        {
            continue;
        }

        strName = nameVal.at(0).trimmed();
        strVal = nameVal.at(1).trimmed();

        if( strName == "OID" )
            strOID = strVal;
        else if( strName == "SN" )
            strSN = strVal;
        else if( strName == "LN" )
            strLN = strVal;

        line = in.readLine();
    }

    file.close();

    return nCount;
}

QString getHexString( const QString& strVal )
{
    char *pHex = NULL;
    BIN binVal = {0,0};
    QString strHex;

    JS_BIN_set( &binVal, (unsigned char *)strVal.toStdString().c_str(), strVal.length() );
    JS_BIN_encodeHex( &binVal, &pHex );

    if( pHex )
    {
        strHex = pHex;
        JS_free( pHex );
    }

    return strHex;
}

QString getHexString( unsigned char *pData, int nDataLen )
{
    BIN binData = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binData, pData, nDataLen );
    JS_BIN_encodeHex( &binData, &pHex );

    QString strHex = pHex;

    JS_BIN_reset( &binData );
    if(pHex) JS_free( pHex );

    return strHex;
}

static char _getPrint( unsigned char c )
{
    if( isprint(c))
      return c;
    else
      return '.';
}

QString getHexView( const char *pName, const BIN *pBin )
{
    int n = 0;
    int left = 0;
    char  sText[16 + 1];
    int length = 0;
    unsigned char *packet = NULL;

    QString strOut;
    QString strTmp;

    if( pName ) strOut += QString( "-- %1 --\n" ).arg( pName );

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    length = pBin->nLen;
    packet = pBin->pVal;

    memset( sText, 0x00, sizeof(sText));

    while (length--)
    {
        if (n % 16 == 0)
        {
            strTmp.sprintf( "%08X ",n);
            strOut += strTmp;
        }

        sText[n%16] = _getPrint( *packet );
        strTmp.sprintf( "%02X ", *packet++);
        strOut += strTmp;

        n++;
        if (n % 8 == 0)
        {
            if (n % 16 == 0)
            {
                strTmp.sprintf( "  %s\n", sText);
                strOut += strTmp;
                memset( sText, 0x00, sizeof(sText));
            }
            else
            {
                strTmp.sprintf(" ");
                strOut += strTmp;
            }
        }
    }

    left = n % 16;
    if( left > 0 )
    {
        for( int i = left; i < 16; i++ )
        {
            strTmp.sprintf( "   " );
            strOut += strTmp;
        }

        if( left < 8 )
        {
            strTmp.sprintf( " " );
            strOut += strTmp;
        }

        strTmp.sprintf( "  %s\n", sText );
        strOut += strTmp;
    }

    return strOut;
}

int getDataLen( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;

    if( nType != DATA_STRING )
    {
        strMsg.remove( QRegExp("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        nLen = strMsg.length() / 2;

        if( strMsg.length() % 2 ) nLen++;

        return nLen;
    }
    else if( nType == DATA_BASE64 )
    {
        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );
        return nLen;
    }

    return strData.length();
}

int getDataLen( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;

    return getDataLen( nType, strData );
}

QString getSymAlg( const QString strAlg, const QString strMode, int nKeyLen )
{
    QString strRes;
    strRes.clear();

    QString strLAlg = strAlg.toLower();
    QString strLMode = strMode.toLower();

    if( (nKeyLen % 8) != 0 ) return strRes;
    if( nKeyLen > 32 ) return strRes;

    if( strAlg.isEmpty() || strMode.isEmpty() ) return strRes;

    if( strLAlg == "des" || strLAlg == "seed" )
        strRes = QString( "%1-%2").arg(strLAlg).arg(strLMode );
    else if( strLAlg == "des3" )
        strRes = QString( "des-ede-%1").arg(strLMode);
    else
        strRes = QString( "%1-%2-%3" ).arg( strLAlg ).arg( nKeyLen * 8 ).arg( strLMode);

    return strRes;
}

int getNameValue( const QString strLine, QString& name, QString& value )
{
    if( strLine.isEmpty() ) return -1;

    QStringList nameVal = strLine.split( "=" );

    if( nameVal.size() >= 1 )
        name = nameVal.at(0).trimmed();

    if( nameVal.size() >= 2 )
        value = nameVal.at(1).trimmed();

    return 0;
}
