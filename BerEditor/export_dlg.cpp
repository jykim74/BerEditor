#include <QFileDialog>
#include <QString>
#include <QFileInfo>

#include "common.h"
#include "export_dlg.h"
#include "ber_applet.h"

static const QString getFormatName( int nFormatType )
{
    switch (nFormatType) {
    case ExportPubPEM:
        return QObject::tr( "PEM public (*.pem)" );
    case ExportPubDER:
        return QObject::tr( "DER public (*.der)" );
    case ExportPriPEM:
        return QObject::tr( "PEM private (*.pem)" );
    case ExportPriDER:
        return QObject::tr( "DER private (*.der)" );
    case ExportCertPEM:
        return QObject::tr( "PEM certificate (*.crt)");
    case ExportCertDER:
        return QObject::tr( "DER certificate (*.cer)" );
    case ExportPFX:
        return QObject::tr( "PKCS12 (*.pfx)" );
    case ExportP8Info:
        return QObject::tr( "PEM PKCS8 Info (*.pk8)" );
    case ExportP8Enc:
        return QObject::tr( "PEM PKCS8 Encrypt (*.pk8)" );
    case ExportCSR_PEM:
        return QObject::tr( "PEM CSR (*.csr)" );
    case ExportCRL_PEM:
        return QObject::tr( "PEM CRL (*.crl)" );
    case ExportPEM:
        return QObject::tr( "PEM (*.pem)" );
    case ExportDER:
        return QObject::tr( "DER (*.der)" );

    default:
        break;
    }

    return "";
}

static const QString getFormatDesc( int nFormatType )
{
    switch (nFormatType) {
    case ExportPubPEM:
        return QObject::tr( "Public key PEM format file" );
    case ExportPubDER:
        return QObject::tr( "Public key DER format file" );
    case ExportPriPEM:
        return QObject::tr( "Unencrypted private key PEM format file" );
    case ExportPriDER:
        return QObject::tr( "Unencrypted private key DER format file" );
    case ExportCertPEM:
        return QObject::tr( "Certificate PEM format file");
    case ExportCertDER:
        return QObject::tr( "Certificate DER format file" );
    case ExportPFX:
        return QObject::tr( "PKCS12 (PFX) format file" );
    case ExportP8Info:
        return QObject::tr( "Unencrypted PKCS8 PEM format file" );
    case ExportP8Enc:
        return QObject::tr( "Encrypted PKCS8 PEM format file" );
    case ExportCSR_PEM:
        return QObject::tr( "CSR PEM format file" );
    case ExportCRL_PEM:
        return QObject::tr( "CRL PEM format file" );
    case ExportPEM:
        return QObject::tr( "PEM format file" );
    case ExportDER:
        return QObject::tr( "DER format file" );

    default:
        break;
    }

    return "Not Defined";
}

static const QString getFormatExtend( int nFormatType )
{
    switch (nFormatType) {
    case ExportPubPEM:
        return "pem";
    case ExportPubDER:
        return "der";
    case ExportPriPEM:
        return "pem";
    case ExportPriDER:
        return "der";
    case ExportCertPEM:
        return "crt";
    case ExportCertDER:
        return "cer";
    case ExportPFX:
        return "pfx";
    case ExportP8Info:
        return "pk8";
    case ExportP8Enc:
        return "pk8";
    case ExportCSR_PEM:
        return "csr";
    case ExportCRL_PEM:
        return "crl";
    case ExportPEM:
        return "pem";
    case ExportDER:
        return "der";

    default:
        break;
    }

    return "pem";
}

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    data_type_ = -1;

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &cert_, 0x00, sizeof(BIN));
    memset( &csr_, 0x00, sizeof(BIN));
    memset( &crl_, 0x00, sizeof(BIN));


    connect( mFindFilenameBtn, SIGNAL(clicked()), this, SLOT(clickFindFilename()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mFormatCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeFormatType(int)));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

ExportDlg::~ExportDlg()
{
    JS_BIN_reset( &pri_key_ );
    JS_BIN_reset( &cert_ );
    JS_BIN_reset( &csr_ );
    JS_BIN_reset( &crl_ );
}

void ExportDlg::initialize()
{

}

void ExportDlg::setName( const QString strName )
{
    mNameText->setText( strName );
    QString strFolder = berApplet->curFolder();

    QString strFilename = QString( "%1/%2.pem" ).arg( strFolder ).arg( strName );
    mFilenameText->setText( strFilename );
}

void ExportDlg::changeFormatType( int index )
{
    int nFormatType = mFormatCombo->currentData().toInt();
    QString strDesc = getFormatDesc( nFormatType );
    mFormatInfoText->setText( strDesc );
    QString strFileName = mFilenameText->text();
    QString strExt = getFormatExtend( mFormatCombo->currentData().toInt());

    QFileInfo fileInfo( strFileName );

    QString strNewName = QString( "%1/%2.%3" ).arg( fileInfo.path() ).arg( fileInfo.baseName() ).arg( strExt );
    mFilenameText->setText( strNewName );
}

void ExportDlg::clickOK()
{
    QDialog::accept();
}

void ExportDlg::clickFindFilename()
{
    int nType = JS_FILE_TYPE_BIN;

    if( data_type_ == DataPriKey )
        nType = JS_FILE_TYPE_PRIKEY;
    else if( data_type_ == DataCert )
        nType = JS_FILE_TYPE_CERT;
    else if( data_type_ == DataCRL )
        nType = JS_FILE_TYPE_CRL;
    else if( data_type_ == DataCSR )
        nType = JS_FILE_TYPE_CSR;

    QString strPath = mFilenameText->text();

    QString strFilename = findSaveFile( this, nType, strPath );
    if( strFilename.length() < 1 ) return;

    mFilenameText->setText( strFilename );
}

void ExportDlg::setPrivateKey( const BIN *pPriKey )
{
    data_type_ = DataPriKey;
    JS_BIN_copy( &pri_key_, pPriKey );

    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
    mFormatCombo->addItem( getFormatName( ExportPriPEM ), ExportPriPEM);
    mFormatCombo->addItem( getFormatName( ExportPriDER ), ExportPriDER);
    mFormatCombo->addItem( getFormatName( ExportP8Info ), ExportP8Info);
    mFormatCombo->addItem( getFormatName( ExportP8Enc ), ExportP8Enc );
}

void ExportDlg::setCert( const BIN *pCert )
{
    data_type_ = DataCert;
    JS_BIN_copy( &cert_, pCert );

    mFormatCombo->addItem( getFormatName( ExportCertPEM ), ExportCertPEM );
    mFormatCombo->addItem( getFormatName( ExportCertDER ), ExportCertDER);
    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
}

void ExportDlg::setCRL( const BIN *pCRL )
{
    data_type_ = DataCRL;
    JS_BIN_copy( &crl_, pCRL );

    mFormatCombo->addItem( getFormatName( ExportCRL_PEM ), ExportCRL_PEM );
    mFormatCombo->addItem( getFormatName( ExportDER ), ExportDER);
}

void ExportDlg::setCSR( const BIN *pCSR )
{
    data_type_ = DataCSR;
    JS_BIN_copy( &csr_, pCSR );

    mFormatCombo->addItem( getFormatName( ExportCSR_PEM ), ExportCSR_PEM );
    mFormatCombo->addItem( getFormatName( ExportDER ), ExportDER);
}

void ExportDlg::setPriKeyAndCert( const BIN *pPriKey, const BIN *pCert )
{
    data_type_ = DataPriKeyCert;
    JS_BIN_copy( &pri_key_, pPriKey );
    JS_BIN_copy( &cert_, pCert );

    mFormatCombo->addItem( getFormatName( ExportPFX ), ExportPFX );

    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
    mFormatCombo->addItem( getFormatName( ExportPriPEM ), ExportPriPEM);
    mFormatCombo->addItem( getFormatName( ExportPriDER ), ExportPriDER);
    mFormatCombo->addItem( getFormatName( ExportP8Info ), ExportP8Info);
    mFormatCombo->addItem( getFormatName( ExportP8Enc ), ExportP8Enc );

    mFormatCombo->addItem( getFormatName( ExportCertPEM ), ExportCertPEM );
    mFormatCombo->addItem( getFormatName( ExportCertDER ), ExportCertDER);
}


int ExportDlg::exportPublic()
{
    if( data_type_ == DataCRL ) return -1;
    if( data_type_ == DataCSR ) return -1;


    return 0;
}

int ExportDlg::exportPrivate()
{
    if( data_type_ == DataCRL ) return -1;
    if( data_type_ == DataCSR ) return -1;
    if( data_type_ == DataCert ) return -1;


    return 0;
}

int ExportDlg::exportCert()
{
    if( data_type_ == DataPriKey ) return -1;
    if( data_type_ == DataCRL ) return -1;
    if( data_type_ == DataCSR ) return -1;
    if( data_type_ == DataCert ) return -1;

    return 0;
}

int ExportDlg::exportCRL()
{
    if( data_type_ != DataCRL ) return -1;

    return 0;
}

int ExportDlg::exportCSR()
{
    if( data_type_ != DataCSR ) return -1;

    return 0;
}

int ExportDlg::exportPFX()
{
    if( data_type_ != DataPriKeyCert ) return -1;

    return 0;
}
