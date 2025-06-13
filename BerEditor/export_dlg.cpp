#include <QFileDialog>
#include <QString>
#include <QFileInfo>

#include "common.h"
#include "export_dlg.h"
#include "ber_applet.h"
#include "js_pki.h"
#include "js_pki_key.h"
#include "js_error.h"
#include "new_passwd_dlg.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "csr_info_dlg.h"
#include "pri_key_info_dlg.h"

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
    case ExportP8InfoPEM:
        return QObject::tr( "PEM PKCS8 Info (*.pk8)" );
    case ExportP8InfoDER:
        return QObject::tr( "DER PKCS8 Info (*.der)" );
    case ExportP8EncPEM:
        return QObject::tr( "PEM PKCS8 Encrypt (*.key)" );
    case ExportP8EncDER:
        return QObject::tr( "DER PKCS8 Encrypt (*.der)" );
    case ExportCSR_PEM:
        return QObject::tr( "PEM CSR (*.csr)" );
    case ExportCSR_DER:
        return QObject::tr( "DER CSR (*.der)" );
    case ExportCRL_PEM:
        return QObject::tr( "PEM CRL (*.crl)" );
    case ExportCRL_DER:
        return QObject::tr( "DER CRL (*.der)" );
    case ExportDH_PEM:
        return QObject::tr( "PEM DH Parameter (*.pem)" );
    case ExportDH_DER:
        return QObject::tr( "DER DH Parameter (*.der)" );

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
    case ExportP8InfoPEM:
        return QObject::tr( "Unencrypted PKCS8 PEM format file" );
    case ExportP8InfoDER:
        return QObject::tr( "Unencrypted PKCS8 DER format file" );
    case ExportP8EncPEM:
        return QObject::tr( "Encrypted PKCS8 PEM format file" );
    case ExportP8EncDER:
        return QObject::tr( "Encrypted PKCS8 DER format file" );
    case ExportCSR_PEM:
        return QObject::tr( "CSR PEM format file" );
    case ExportCSR_DER:
        return QObject::tr( "CSR DER format file" );
    case ExportCRL_PEM:
        return QObject::tr( "CRL PEM format file" );
    case ExportCRL_DER:
        return QObject::tr( "CRL DER format file" );
    case ExportDH_PEM:
        return QObject::tr( "DH Parameter PEM format file" );
    case ExportDH_DER:
        return QObject::tr( "DH Parameter DER format file" );

    default:
        break;
    }

    return "Not Defined";
}

static const QString getFormatExtend( int nFormatType )
{
    switch (nFormatType) {
    case ExportPubPEM:
    case ExportDH_PEM:
        return "pem";
    case ExportPubDER:
    case ExportDH_DER:
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
    case ExportP8InfoPEM:
        return "pk8";
    case ExportP8InfoDER:
        return "der";
    case ExportP8EncPEM:
        return "key";
    case ExportP8EncDER:
        return "der";
    case ExportCSR_PEM:
        return "csr";
    case ExportCSR_DER:
        return "der";
    case ExportCRL_PEM:
        return "crl";
    case ExportCRL_DER:
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
    key_type_ = -1;

    memset( &pri_key_, 0x00, sizeof(BIN));
    memset( &pub_key_, 0x00, sizeof(BIN));
    memset( &cert_, 0x00, sizeof(BIN));
    memset( &csr_, 0x00, sizeof(BIN));
    memset( &crl_, 0x00, sizeof(BIN));
    memset( &param_, 0x00, sizeof(BIN));

    connect( mFindFilenameBtn, SIGNAL(clicked()), this, SLOT(clickFindFilename()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
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
    JS_BIN_reset( &pub_key_ );
    JS_BIN_reset( &cert_ );
    JS_BIN_reset( &csr_ );
    JS_BIN_reset( &crl_ );
    JS_BIN_reset( &param_ );
}

void ExportDlg::initialize()
{

}

void ExportDlg::setName( const QString strName )
{
    mNameText->setText( strName );
    QString strFolder = berApplet->curPath();

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
    int ret = 0;
    int nExportType = mFormatCombo->currentData().toInt();

    QString strFilename = mFilenameText->text();

    if( QFileInfo::exists( strFilename ) == true )
    {
        bool bVal = berApplet->yesOrNoBox( tr( "That file name already exists. Do you want to overwrite it?" ), this );
        if( bVal == false ) return;
    }

    switch ( nExportType ) {
    case ExportPubPEM:
    case ExportPubDER:
        ret = exportPublic();
        break;

    case ExportPriPEM:
    case ExportPriDER:
        ret = exportPrivate();
        break;

    case ExportCertPEM:
    case ExportCertDER:
        ret = exportCert();
        break;

    case ExportPFX:
        ret = exportPFX();
        break;

    case ExportP8InfoPEM:
    case ExportP8InfoDER:
        ret = exportP8Info();
        break;

    case ExportP8EncPEM:
    case ExportP8EncDER:
        ret = exportP8Enc();
        break;

    case ExportCSR_PEM:
    case ExportCSR_DER:
        ret = exportCSR();
        break;

    case ExportCRL_PEM:
    case ExportCRL_DER:
        ret = exportCRL();
        break;

    case ExportDH_PEM:
    case ExportDH_DER:
        ret = exportDHParam();
        break;

    default:
        break;
    }

    if( ret == 0 ) QDialog::accept();
}

void ExportDlg::clickFindFilename()
{
    QString strPath = mFilenameText->text();
    QString strFilter = mFormatCombo->currentText();
    QString strFilename = berApplet->findSaveFile( this, strFilter, strPath );

    if( strFilename.length() < 1 ) return;

    mFilenameText->setText( strFilename );
}

void ExportDlg::clickView()
{
    if( data_type_ == DataPriKey )
    {
        PriKeyInfoDlg priKeyInfo;
        priKeyInfo.setPrivateKey( &pri_key_ );
        priKeyInfo.exec();
    }
    else if( data_type_ == DataPubKey )
    {
        PriKeyInfoDlg priKeyInfo;
        priKeyInfo.setPublicKey( &pub_key_ );
        priKeyInfo.exec();
    }
    else if( data_type_ == DataCert )
    {
        CertInfoDlg certInfo;
        certInfo.setCertBIN( &cert_ );
        certInfo.exec();
    }
    else if( data_type_ == DataCSR )
    {
        CSRInfoDlg csrInfo;
        csrInfo.setReqBIN( &csr_ );
        csrInfo.exec();
    }
    else if( data_type_ == DataCRL )
    {
        CRLInfoDlg crlInfo;
        crlInfo.setCRL_BIN( &crl_ );
        crlInfo.exec();
    }
    else
    {
        berApplet->warningBox( tr( "This data is not supported."), this );
    }
}

void ExportDlg::setPrivateKey( const BIN *pPriKey )
{
    data_type_ = DataPriKey;
    JS_BIN_copy( &pri_key_, pPriKey );
    key_type_ = JS_PKI_getPriKeyType( &pri_key_ );
    mAlgText->setText( JS_PKI_getKeyTypeName( key_type_ ));

    mTitleLabel->setText( tr( "Private Key Export" ));

    mFormatCombo->addItem( getFormatName( ExportP8EncPEM ), ExportP8EncPEM );
    mFormatCombo->addItem( getFormatName( ExportP8EncDER ), ExportP8EncDER );
    mFormatCombo->addItem( getFormatName( ExportPriPEM ), ExportPriPEM);
    mFormatCombo->addItem( getFormatName( ExportPriDER ), ExportPriDER);
    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
    mFormatCombo->addItem( getFormatName( ExportP8InfoPEM ), ExportP8InfoPEM);
    mFormatCombo->addItem( getFormatName( ExportP8InfoDER ), ExportP8InfoDER);
}

void ExportDlg::setPublicKey( const BIN *pPubKey )
{
    data_type_ = DataPubKey;
    JS_BIN_copy( &pub_key_, pPubKey );
    key_type_ = JS_PKI_getPubKeyType( &pub_key_ );
    mAlgText->setText( JS_PKI_getKeyTypeName( key_type_ ));

    mTitleLabel->setText( tr( "Public Key Export" ));

    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
}

void ExportDlg::setCert( const BIN *pCert )
{
    data_type_ = DataCert;
    JS_BIN_copy( &cert_, pCert );
    key_type_ = JS_PKI_getCertKeyType( &cert_ );
    mAlgText->setText( JS_PKI_getKeyTypeName( key_type_ ));

    mTitleLabel->setText( tr( "Certificate Export" ));

    mFormatCombo->addItem( getFormatName( ExportCertPEM ), ExportCertPEM );
    mFormatCombo->addItem( getFormatName( ExportCertDER ), ExportCertDER);
    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
}

void ExportDlg::setCRL( const BIN *pCRL )
{
    data_type_ = DataCRL;
    JS_BIN_copy( &crl_, pCRL );
    key_type_ = -1;
    mAlgText->setText( "CRL" );

    mTitleLabel->setText( tr( "CRL Export" ));

    mFormatCombo->addItem( getFormatName( ExportCRL_PEM ), ExportCRL_PEM );
    mFormatCombo->addItem( getFormatName( ExportCRL_DER ), ExportCRL_DER);
}

void ExportDlg::setCSR( const BIN *pCSR )
{
    data_type_ = DataCSR;
    JS_BIN_copy( &csr_, pCSR );
    key_type_ = JS_PKI_getCSRKeyType( pCSR );
    mAlgText->setText( JS_PKI_getKeyTypeName( key_type_ ));

    mTitleLabel->setText( tr( "CSR Export" ));

    mFormatCombo->addItem( getFormatName( ExportCSR_PEM ), ExportCSR_PEM );
    mFormatCombo->addItem( getFormatName( ExportCSR_DER ), ExportCSR_DER);
    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);
}

void ExportDlg::setDHParam( const BIN *pParam )
{
    data_type_ = DataDHParam;
    key_type_ = -1;

    mAlgText->setText( "DH" );
    JS_BIN_copy( &param_, pParam );
    mTitleLabel->setText( tr( "DH Parameter Export" ));

    mFormatCombo->addItem( getFormatName( ExportDH_PEM ), ExportDH_PEM );
    mFormatCombo->addItem( getFormatName( ExportDH_DER ), ExportDH_DER );
}

void ExportDlg::setPriKeyAndCert( const BIN *pPriKey, const BIN *pCert )
{
    data_type_ = DataPriKeyCert;
    JS_BIN_copy( &pri_key_, pPriKey );
    JS_BIN_copy( &cert_, pCert );

    mTitleLabel->setText( tr( "Certificate and Private Key Export" ));

    key_type_ = JS_PKI_getCertKeyType( &cert_ );
    mAlgText->setText( JS_PKI_getKeyTypeName( key_type_ ));

    mFormatCombo->addItem( getFormatName( ExportPFX ), ExportPFX );

    mFormatCombo->addItem( getFormatName( ExportCertPEM ), ExportCertPEM );
    mFormatCombo->addItem( getFormatName( ExportCertDER ), ExportCertDER);

    mFormatCombo->addItem( getFormatName( ExportP8EncPEM ), ExportP8EncPEM );
    mFormatCombo->addItem( getFormatName( ExportP8EncDER ), ExportP8EncDER );

    mFormatCombo->addItem( getFormatName( ExportPriPEM ), ExportPriPEM);
    mFormatCombo->addItem( getFormatName( ExportPriDER ), ExportPriDER);

    mFormatCombo->addItem( getFormatName( ExportPubPEM ), ExportPubPEM );
    mFormatCombo->addItem( getFormatName( ExportPubDER ), ExportPubDER);

    mFormatCombo->addItem( getFormatName( ExportP8InfoPEM ), ExportP8InfoPEM);
    mFormatCombo->addItem( getFormatName( ExportP8InfoDER ), ExportP8InfoDER);
}


int ExportDlg::exportPublic()
{
    int ret = -1;
    int nExportType = -1;
    BIN binPub = {0,0};
    QString strFilename = mFilenameText->text();

    if( data_type_ == DataCRL ) return -1;

    if( data_type_ == DataPriKey )
    {
        JS_PKI_getPubKeyFromPri( key_type_, &pri_key_, &binPub );
    }
    else if( data_type_ == DataPubKey )
    {
        JS_BIN_copy( &binPub, &pub_key_ );
    }
    else if( data_type_ == DataCSR )
    {
        JS_PKI_getPubKeyFromCSR( &csr_, &binPub );
    }
    else if( data_type_ == DataCert || data_type_ == DataPriKeyCert )
    {
        JS_PKI_getPubKeyFromCert( &cert_, &binPub );
    }
    else
    {
        berApplet->warningBox( tr( "invalid service: %1").arg( data_type_ ), this);
        ret = -1;
        goto end;
    }

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportPubPEM )
    {
        ret = JS_BIN_writePEM( &binPub, JS_PEM_TYPE_PUBLIC_KEY, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportPubDER )
    {
        ret = JS_BIN_fileWrite( &binPub, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "Public Key export successfully" ), this );
        ret = JSR_OK;
    }

end :
    JS_BIN_reset( &binPub );
    return ret;
}

int ExportDlg::exportPrivate()
{
    int ret = -1;
    int nExportType = -1;
    QString strFilename = mFilenameText->text();

    if( data_type_ == DataPubKey ) return -1;
    if( data_type_ == DataCRL ) return -1;
    if( data_type_ == DataCSR ) return -1;
    if( data_type_ == DataCert ) return -1;

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportPriPEM )
    {
        ret = JS_BIN_writePEM( &pri_key_, JS_PEM_TYPE_PRIVATE_KEY, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportPriDER )
    {
        ret = JS_BIN_fileWrite( &pri_key_, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "Private Key export successfully" ), this );
        ret = JSR_OK;
    }

    return ret;
}

int ExportDlg::exportCert()
{
    int ret = -1;
    int nExportType = -1;
    QString strFilename = mFilenameText->text();

    if( data_type_ == DataPubKey ) return -1;
    if( data_type_ == DataPriKey ) return -1;
    if( data_type_ == DataCRL ) return -1;
    if( data_type_ == DataCSR ) return -1;

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportCertPEM )
    {
        ret = JS_BIN_writePEM( &cert_, JS_PEM_TYPE_CERTIFICATE, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportCertDER )
    {
        ret = JS_BIN_fileWrite( &cert_, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "Certificate export successfully" ), this );
        ret = JSR_OK;
    }

    return ret;
}

int ExportDlg::exportCRL()
{
    int ret = -1;
    int nExportType = -1;
    QString strFilename = mFilenameText->text();

    if( data_type_ != DataCRL ) return -1;

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportCRL_PEM )
    {
        ret = JS_BIN_writePEM( &crl_, JS_PEM_TYPE_CERTIFICATE, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportCRL_DER )
    {
        ret = JS_BIN_fileWrite( &crl_, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "CRL export successfully" ), this );
        ret = JSR_OK;
    }

    return ret;
}

int ExportDlg::exportCSR()
{
    int ret = -1;
    int nExportType = -1;
    QString strFilename = mFilenameText->text();

    if( data_type_ != DataCSR ) return -1;

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportCSR_PEM )
    {
        ret = JS_BIN_writePEM( &csr_, JS_PEM_TYPE_CSR, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportCSR_DER )
    {
        ret = JS_BIN_fileWrite( &csr_, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "CSR export successfully" ), this );
        ret = JSR_OK;
    }

    return ret;
}

int ExportDlg::exportPFX()
{
    int ret = -1;
    BIN binPFX = {0,0};
    int nExportType = mFormatCombo->currentData().toInt();
    QString strFilename = mFilenameText->text();
    QString strPass;

    if( data_type_ != DataPriKeyCert ) return -1;

    if( nExportType != ExportPFX ) return -1;

    NewPasswdDlg newPass;

    if( newPass.exec() != QDialog::Accepted )
        return -1;

    strPass = newPass.mPasswdText->text();

    ret = JS_PKI_encodePFX( &binPFX, key_type_, strPass.toStdString().c_str(), -1, &pri_key_, &cert_ );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to encrypt PFX: %1").arg(ret), this);
        goto end;
    }

    ret = JS_BIN_fileWrite( &binPFX, strFilename.toLocal8Bit().toStdString().c_str() );
    if( ret > 0 )
    {
        berApplet->messageBox( tr( "PFX export successfully" ), this );
        ret = JSR_OK;
    }

end :
    JS_BIN_reset( &binPFX );
    return ret;
}

int ExportDlg::exportP8Enc()
{
    int ret = -1;
    BIN binEncPri = {0,0};
    int nExportType = mFormatCombo->currentData().toInt();
    QString strFilename = mFilenameText->text();
    QString strPass;

    if( data_type_ != DataPriKey && data_type_ != DataPriKeyCert )
        return -1;

    if( nExportType != ExportP8EncPEM && nExportType != ExportP8EncDER ) return -1;

    NewPasswdDlg newPass;

    if( newPass.exec() != QDialog::Accepted )
        return -1;

    strPass = newPass.mPasswdText->text();

    ret = JS_PKI_encryptPrivateKey( key_type_, -1, strPass.toStdString().c_str(), &pri_key_, NULL, &binEncPri );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "fail to encrypt private key: %1").arg(ret), this);
        goto end;
    }

    if( nExportType == ExportP8EncPEM )
        ret = JS_BIN_writePEM( &binEncPri, JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY, strFilename.toLocal8Bit().toStdString().c_str() );
    else
        ret = JS_BIN_fileWrite( &binEncPri, strFilename.toLocal8Bit().toStdString().c_str() );

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "Encrypted privateKey export successfully" ), this );
        ret = JSR_OK;
    }

end :
    JS_BIN_reset( &binEncPri );
    return ret;
}

int ExportDlg::exportP8Info()
{
    int ret = -1;
    int nExportType = mFormatCombo->currentData().toInt();
    BIN binP8 = {0,0};
    QString strFilename = mFilenameText->text();

    if( data_type_ != DataPriKey && data_type_ != DataPriKeyCert )
        return -1;

    ret = JS_PKI_encodePrivateKeyInfo( key_type_, &pri_key_, &binP8 );
    if( ret != 0 )
    {
        goto end;
    }

    if( nExportType == ExportP8InfoPEM )
    {
        ret = JS_BIN_writePEM( &binP8, JS_PEM_TYPE_PRIVATE_KEY, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportP8EncDER )
    {
        ret = JS_BIN_fileWrite( &binP8, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "PKCS8 Info export successfully" ), this );
        ret = JSR_OK;
    }

end :
    JS_BIN_reset( &binP8 );
    return ret;
}

int ExportDlg::exportDHParam()
{
    int ret = -1;
    int nExportType = -1;
    QString strFilename = mFilenameText->text();

    if( data_type_ != DataDHParam ) return -1;

    nExportType = mFormatCombo->currentData().toInt();

    if( nExportType == ExportDH_PEM )
    {
        ret = JS_BIN_writePEM( &param_, JS_PEM_TYPE_DH_PARAMETERS, strFilename.toLocal8Bit().toStdString().c_str() );
    }
    else if( nExportType == ExportDH_DER )
    {
        ret = JS_BIN_fileWrite( &param_, strFilename.toLocal8Bit().toStdString().c_str() );
    }

    if( ret > 0 )
    {
        berApplet->messageBox( tr( "DH Parameter export successfully" ), this );
        ret = JSR_OK;
    }

    return ret;
}
