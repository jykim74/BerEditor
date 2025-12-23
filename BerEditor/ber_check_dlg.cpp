#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "ber_check_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "common.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "csr_info_dlg.h"
#include "pri_key_info_dlg.h"
#include "cms_info_dlg.h"
#include "passwd_dlg.h"

#include "js_pki.h"
#include "js_pki_tools.h"

const QStringList sTypeList = {
    JS_PKI_BER_NAME_CERTIFICATE, JS_PKI_BER_NAME_CRL, JS_PKI_BER_NAME_CSR,
    JS_PKI_BER_NAME_PUB_KEY, JS_PKI_BER_NAME_PRI_KEY, JS_PKI_BER_NAME_PRI_KEY_INFO,
    JS_PKI_BER_NAME_ENC_PRI_KEY, JS_PKI_BER_NAME_CMS, JS_PKI_BER_NAME_PKCS7
};

BERCheckDlg::BERCheckDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    setAcceptDrops(true);

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mClearBtn, SIGNAL(clicked(bool)), this, SLOT(clickClear()));
    connect( mFileCheck, SIGNAL(clicked()), this, SLOT(checkFile()));
    connect( mFileFindBtn, SIGNAL(clicked(bool)), this, SLOT(clickFileFind()));
    connect( mFormatCheckBtn, SIGNAL(clicked(bool)), this, SLOT(clickCheckFormat()));
    connect( mTypeCheckBtn, SIGNAL(clicked(bool)), this, SLOT(clickCheckType()));

    connect( mSrcTypeCombo, SIGNAL(currentIndexChanged(int)), SLOT(changeSrcType()));
    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(changeSrc()));

    connect( mViewBtn, SIGNAL(clicked(bool)), this, SLOT(clickView()));
    connect( mDecodeBtn, SIGNAL(clicked()), this, SLOT(clickDecode()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mViewBtn->setFixedWidth(34);
    mDecodeBtn->setFixedWidth(34);
#endif

    initialize();
    mTypeCheckBtn->setDefault(true);
    mSrcText->setFocus();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

BERCheckDlg::~BERCheckDlg()
{

}

void BERCheckDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void BERCheckDlg::dropEvent(QDropEvent *event)
{
    char *pOut = NULL;

    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            berApplet->log( QString( "url: %1").arg( url.toLocalFile() ));

            if( mFileCheck->isChecked() == true )
                mFilePathText->setText( url.toLocalFile() );
            else
            {
                BIN binData = {0,0};
                JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binData );
                mSrcTypeCombo->setCurrentText( kDataHex );
                mSrcText->setPlainText( getHexString( &binData ) );
                JS_BIN_reset( &binData );
            }

            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
}

void BERCheckDlg::initUI()
{
    mSrcText->setAcceptDrops(false);
    mFormatCombo->addItem( "" );
    mFormatCombo->addItems( sTypeList );
    mSrcTypeCombo->addItems( kDataBinTypeList );

    QString strList;

    for( int i = 0; i < sTypeList.size(); i++ )
    {
        QString strType = sTypeList.at(i);

        strList += strType;
        strList += " ";
    }

    mCheckListLabel->setText( strList );
}

void BERCheckDlg::initialize()
{
    checkFile();
}

int BERCheckDlg::readSrc( BIN *pSrc )
{
    int ret = 0;
    QString strPath = mFilePathText->text();

    if( mFileCheck->isChecked() == true )
    {
        if( strPath.length() < 1 )
        {
            berApplet->warningBox( tr( "find a source" ), this );
            mFilePathText->setFocus();
            return -1;
        }

        ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), pSrc );
        if( ret < 0 ) return ret;
    }
    else
    {
        QString strData = mSrcText->toPlainText();
        QString strType = mSrcTypeCombo->currentText();

        if( strData.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a source data" ), this );
            mSrcText->setFocus();
            return -2;
        }

        ret = getBINFromString( pSrc, strType, strData );
        FORMAT_WARN_RET(ret);
    }

    return 0;
}

void BERCheckDlg::clickClear()
{
    mFilePathText->clear();
    mSrcText->clear();
}

void BERCheckDlg::changeSrcType()
{
    changeSrc();
}

void BERCheckDlg::checkFile()
{
    bool bVal = mFileCheck->isChecked();

    mFilePathText->setEnabled( bVal );
    mFileFindBtn->setEnabled( bVal );

    mSrcLabel->setEnabled( !bVal );
    mSrcTypeCombo->setEnabled( !bVal );
    mSrcText->setEnabled( !bVal );
    mSrcLenText->setEnabled( !bVal );
}

void BERCheckDlg::changeSrc()
{
    QString strType = mSrcTypeCombo->currentText();
    QString strSrc = mSrcText->toPlainText();

    QString strLen = getDataLenString( strType, strSrc );
    mSrcLenText->setText( QString("%1").arg( strLen ));
}

void BERCheckDlg::clickFileFind()
{
    QString strPath = mFilePathText->text();

    QString strFileName = berApplet->findFile( this, JS_FILE_TYPE_BER, strPath );
    if( strFileName.length() < 1 ) return;

    mFilePathText->setText( strFileName );
}


void BERCheckDlg::clickCheckFormat()
{
    int ret = 0;

    char sError[1024];
    BIN binSrc = {0,0};
    QString strFormat = mFormatCombo->currentText();

    if( strFormat.length() < 1 )
    {
        berApplet->warningBox( tr( "No format selected" ), this );
        mFormatCombo->setFocus();
        return;
    }

    memset( sError, 0x00, sizeof(sError));

    ret = readSrc( &binSrc );
    if( ret != 0 )
    {
        berApplet->warningBox( tr( "Failed to read source: %1" ).arg(JERR(ret)), this );
        return;
    }

    if( ret == 0 && binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        return;
    }

    if( strFormat == JS_PKI_BER_NAME_CERTIFICATE )
        ret = JS_PKI_checkCertFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CRL )
        ret = JS_PKI_checkCRLFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CSR )
        ret = JS_PKI_checkCSRFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PUB_KEY )
        ret = JS_PKI_checkPubKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PRI_KEY )
        ret = JS_PKI_checkPriKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PRI_KEY_INFO )
        ret = JS_PKI_checkPriKeyInfoFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_ENC_PRI_KEY )
        ret = JS_PKI_checkEncPriKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CMS )
        ret = JS_PKI_checkCMSFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PKCS7 )
        ret = JS_PKI_checkPKCS7Format( &binSrc, sError );
    else
    {
        goto end;
    }

    if( ret == JSR_OK )
    {
        berApplet->messageBox( tr( "This source is in the correct %1 format" ).arg( strFormat ), this );
    }
    else
    {
        berApplet->warningBox( tr( "This source is not in %1 format: %2:%3" ).arg( strFormat ).arg( sError ).arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binSrc );
}

void BERCheckDlg::clickCheckType()
{
    int ret = 0;
    BIN binSrc = {0,0};

    ret = readSrc( &binSrc );
    if( ret != 0 ) goto end;

    if( ret == JSR_OK && binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        return;
    }

    ret = JS_PKI_getBERFormat( &binSrc );
    if( ret > 0 )
    {
        QString strFormat = JS_PKI_getBERName( ret );
        mFormatCombo->setCurrentText( strFormat );
        berApplet->messageBox( tr( "BER data format is %1" ).arg( JS_PKI_getBERName(ret)), this );
    }
    else
    {
        mFormatCombo->setCurrentText( "" );
        berApplet->warningBox( tr( "The data is not in the format to be checked or is incorrect: %1" ).arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binSrc );
}

void BERCheckDlg::clickView()
{
    int ret = -1;

    char sError[1024];
    BIN binSrc = {0,0};
    QString strFormat = mFormatCombo->currentText();

    if( strFormat.length() < 1 )
    {
        berApplet->warningBox( tr( "No format selected" ), this );
        mFormatCombo->setFocus();
        return;
    }

    memset( sError, 0x00, sizeof(sError));

    ret = readSrc( &binSrc );
    if( ret != 0 ) return;

    if( ret == 0 && binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        return;
    }

    if( strFormat == JS_PKI_BER_NAME_CERTIFICATE )
        ret = JS_PKI_checkCertFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CRL )
        ret = JS_PKI_checkCRLFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CSR )
        ret = JS_PKI_checkCSRFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PUB_KEY )
        ret = JS_PKI_checkPubKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PRI_KEY )
        ret = JS_PKI_checkPriKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PRI_KEY_INFO )
        ret = JS_PKI_checkPriKeyInfoFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_ENC_PRI_KEY )
        ret = JS_PKI_checkEncPriKeyFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_CMS )
        ret = JS_PKI_checkCMSFormat( &binSrc, sError );
    else if( strFormat == JS_PKI_BER_NAME_PKCS7 )
        ret = JS_PKI_checkPKCS7Format( &binSrc, sError );


    if( ret == JSR_OK )
    {
        if( strFormat == JS_PKI_BER_NAME_CERTIFICATE )
        {
            CertInfoDlg certInfo;
            certInfo.setCertBIN( &binSrc );
            certInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_CRL )
        {
            CRLInfoDlg crlInfo;
            crlInfo.setCRL_BIN( &binSrc );
            crlInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_CSR )
        {
            CSRInfoDlg csrInfo;
            csrInfo.setReqBIN( &binSrc );
            csrInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_PUB_KEY )
        {
            PriKeyInfoDlg priKeyInfo;
            priKeyInfo.setPublicKey( &binSrc );
            priKeyInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_PRI_KEY )
        {
            PriKeyInfoDlg priKeyInfo;
            priKeyInfo.setPrivateKey( &binSrc );
            priKeyInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_PRI_KEY_INFO )
        {
            BIN binPri = {0,0};
            JS_PKI_decodePrivateKeyInfo( &binSrc, &binPri );

            PriKeyInfoDlg priKeyInfo;
            priKeyInfo.setPrivateKey( &binPri );
            priKeyInfo.exec();
            JS_BIN_reset( &binPri );
        }
        else if( strFormat == JS_PKI_BER_NAME_ENC_PRI_KEY )
        {
            PasswdDlg passDlg;
            QString strPass;
            BIN binPri = {0,0};
            PriKeyInfoDlg priKeyInfo;

            if( passDlg.exec() != QDialog::Accepted )
                goto end;

            strPass = passDlg.mPasswdText->text();

            ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binSrc, NULL, &binPri );
            if( ret != 0 )
            {
                berApplet->warningBox( tr( "fail to decrypt private key: %1").arg(ret), this);
                goto end;
            }

            priKeyInfo.setPrivateKey( &binPri );
            priKeyInfo.exec();
        }
        else if( strFormat == JS_PKI_BER_NAME_CMS || strFormat == JS_PKI_BER_NAME_PKCS7)
        {
            CMSInfoDlg cmsInfo;
            cmsInfo.setCMS( &binSrc );
            cmsInfo.exec();
        }
    }
    else
    {
        berApplet->warningBox( tr( "This source is not in %1 format: %2:%3" ).arg( strFormat ).arg( sError ).arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binSrc );
}

void BERCheckDlg::clickDecode()
{
    int ret = -1;

    char sError[1024];
    BIN binSrc = {0,0};
    QString strFormat = mFormatCombo->currentText();

    if( strFormat.length() < 1 )
    {
        berApplet->warningBox( tr( "No format selected" ), this );
        mFormatCombo->setFocus();
        return;
    }

    memset( sError, 0x00, sizeof(sError));

    ret = readSrc( &binSrc );
    if( ret != 0 ) return;

    if( ret == 0 && binSrc.nLen <= 0 )
    {
        berApplet->warningBox( tr( "There is no input value or the input type is incorrect." ), this );
        return;
    }

    berApplet->decodeTitle( &binSrc, strFormat );

end :

    JS_BIN_reset( &binSrc );
}

