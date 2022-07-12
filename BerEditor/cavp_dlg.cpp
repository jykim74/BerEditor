#include <QStringList>
#include <QDir>
#include <QTextStream>
#include <QThread>
#include <QButtonGroup>

#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"

#include "cavp_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"

const QStringList kSymAlgList = { "AES", "ARIA", "SEED" };
const QStringList kSymModeList = { "ECB", "CBC", "CTR", "CFB", "OFB" };
const QStringList kAEAlgList = { "AES", "ARIA" };
const QStringList kAEModeList = { "GCM", "CCM" };
const QStringList kAETypeList = { "AE", "AD" };
const QStringList kSymTypeList = { "KAT", "MCT", "MMT" };
const QStringList kHashAlgList = { "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
const QStringList kHashTypeList = { "Short", "Long", "Monte" };

const QStringList kECDHType = { "KAKAT", "PKV", "KPG" };
const QStringList kECDSAType = { "KPG", "PKV", "SGT", "SVT" };
const QStringList kRSAESType = { "DET", "ENT", "KGT" };
const QStringList kRSA_PSSType = { "KPG", "SGT", "SVT" };

const QStringList kDRBGAlgList = { "ARIA-128-CTR", "ARIA-192-CTR", "ARIA-256-CTR", "AES-128-CTR", "AES-192-CTR", "AES-256-CTR" };


CAVPDlg::CAVPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mECC_ECDSARadio, SIGNAL(clicked()), this, SLOT(clickECC_ECDSARadio()));
    connect( mECC_ECDHRadio, SIGNAL(clicked()), this, SLOT(clickECC_ECDHRadio()));
    connect( mRSA_ESRadio, SIGNAL(clicked()), this, SLOT(clickRSA_ESRadio()));
    connect( mRSA_PSSRadio, SIGNAL(clicked()), this, SLOT(clickRSA_PSSRadio()));

    connect( mSymMCTKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTKeyChanged(const QString&)));
    connect( mSymMCTIVText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTIVChanged(const QString&)));
    connect( mSymMCTPTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTPTChanged(const QString&)));
    connect( mSymMCTCTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTCTChanged(const QString&)));

    connect( mSymMCTLastKeyText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTLastKeyChanged(const QString&)));
    connect( mSymMCTLastIVText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTLastIVChanged(const QString&)));
    connect( mSymMCTLastPTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTLastPTChanged(const QString&)));
    connect( mSymMCTLastCTText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTLastCTChanged(const QString&)));

    connect( mHashMCTSeedText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTSHA256SeedChanged(const QString&)));
    connect( mHashMCTFirstMDText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTSHA256FirstMDChanged(const QString&)));
    connect( mHashMCTLastMDText, SIGNAL(textChanged(const QString&)), this, SLOT(MCTSHA256LastMDChanged(const QString&)));

    connect( mDRBG2EntropyInputText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2EntropyInputChanged(const QString&)));
    connect( mDRBG2NonceText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2NonceChanged(const QString&)));
    connect( mDRBG2PersonalStringText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2PersonalStringChanged(const QString&)));
    connect( mDRBG2EntropyInputReseedText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2EntropyInputReseedChanged(const QString&)));
    connect( mDRBG2AdditionalInputReseedText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2AdditionalInputReseedChanged(const QString&)));
    connect( mDRBG2AdditionalInputText, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2AdditionalInputChanged(const QString&)));
    connect( mDRBG2AdditionalInput2Text, SIGNAL(textChanged(const QString&)), this, SLOT(DRBG2AdditionalInput2Changed(const QString&)));
    connect( mDRBG2ReturnedBitsText, SIGNAL(textChanged()), this, SLOT(DRBG2ReturnedBitsChanged()));

    connect( mSymFindBtn, SIGNAL(clicked()), this, SLOT(clickSymFind() ));
    connect( mSymRunBtn, SIGNAL(clicked()), this, SLOT(clickSymRun() ));

    connect( mAEFindBtn, SIGNAL(clicked()), this, SLOT(clickAEFind() ));
    connect( mAERunBtn, SIGNAL(clicked()), this, SLOT(clickAERun() ));

    connect( mHashFindBtn, SIGNAL(clicked()), this, SLOT(clickHashFind() ));
    connect( mHashRunBtn, SIGNAL(clicked()), this, SLOT(clickHashRun() ));

    connect( mHMACFindBtn, SIGNAL(clicked()), this, SLOT(clickHMACFind() ));
    connect( mHMACRunBtn, SIGNAL(clicked()), this, SLOT(clickHMACRun() ));

    connect( mECCFindBtn, SIGNAL(clicked()), this, SLOT(clickECCFind() ));
    connect( mECCRunBtn, SIGNAL(clicked()), this, SLOT(clickECCRun() ));

    connect( mRSAFindBtn, SIGNAL(clicked()), this, SLOT(clickRSAFind() ));
    connect( mRSARunBtn, SIGNAL(clicked()), this, SLOT(clickRSARun() ));

    connect( mDRBGFindBtn, SIGNAL(clicked()), this, SLOT(clickDRBGFind() ));
//    connect( mDRBGTestBtn, SIGNAL(clicked()), this, SLOT(clickDRBGTest()));
    connect( mDRBGRunBtn, SIGNAL(clicked()), this, SLOT(clickDRBGRun() ));

    connect( mPBKDFFindBtn, SIGNAL(clicked()), this, SLOT(clickPBKDFFind() ));
    connect( mPBKDFRunBtn, SIGNAL(clicked()), this, SLOT(clickPBKDFRun() ));

    connect( mSymMCTRunBtn, SIGNAL(clicked()), this, SLOT(clickSymMCTRun()));
    connect( mSymMCTClearBtn, SIGNAL(clicked()), this, SLOT(clickSymMCTClear()));
    connect( mHashMCTRunBtn, SIGNAL(clicked()), this, SLOT(clickHashMCTRun()));
    connect( mHashMCTClearBtn, SIGNAL(clicked()), this, SLOT(clickHashMCTClear()));

    connect( mDRBG2ClearBtn, SIGNAL(clicked()), this, SLOT(clickDRBG2Clear()));
    connect( mDRBG2RunBtn, SIGNAL(clicked()), this, SLOT(clickDRBG2Run()));

    initialize();
}

CAVPDlg::~CAVPDlg()
{

}

void CAVPDlg::initialize()
{
    tabWidget->setCurrentIndex(0);

    mSymAlgCombo->addItems( kSymAlgList );
    mSymModeCombo->addItems( kSymModeList );
    mSymTypeCombo->addItems( kSymTypeList );

    mAEAlgCombo->addItems( kAEAlgList );
    mAEModeCombo->addItems( kAEModeList );
    mAETypeCombo->addItems( kAETypeList );

    mHashAlgCombo->addItems( kHashAlgList );
    mHashTypeCombo->addItems( kHashTypeList );

    mHMACHashCombo->addItems( kHashAlgList );

    mSymMCTAlgCombo->addItems( kSymAlgList );
    mSymMCTModeCombo->addItems( kSymModeList );
    mHashMCTAlgCombo->addItems( kHashAlgList );

    mPBKDFAlgCombo->addItems( kHashAlgList );

    QButtonGroup *pECCGroup = new QButtonGroup();
    pECCGroup->addButton( mECC_ECDSARadio );
    pECCGroup->addButton(mECC_ECDHRadio );
    mECC_ECDSARadio->setChecked(true);
    clickECC_ECDSARadio();

    QButtonGroup *pRSAGroup = new QButtonGroup();
    pRSAGroup->addButton( mRSA_ESRadio );
    pRSAGroup->addButton( mRSA_PSSRadio );
    mRSA_PSSRadio->setChecked(true);
    clickRSA_ESRadio();

    mDRBGAlgCombo->addItems( kDRBGAlgList );
    mDRBGUseDFCheck->setChecked(true);

    mDRBG2AlgCombo->addItems( kDRBGAlgList );
    mDRBG2UseDFCheck->setChecked( true );
    mDRBG2RandLenText->setText( "512" );
}

QString CAVPDlg::getRspFile(const QString &reqFileName )
{
    QFileInfo fileInfo;
    fileInfo.setFile( reqFileName );


    QString fileName = fileInfo.baseName();
    QString extName = fileInfo.completeSuffix();
    QString filePath = fileInfo.canonicalPath();

    QString fileRspName = QString( "%1.rsp" ).arg( fileName );
    QString strPath = QString( "%1/CAVP_RSP/%2").arg( filePath ).arg( fileRspName );

    berApplet->log( QString( "RspName: %1").arg(strPath));

    return strPath;
}

void CAVPDlg::logRsp( const QString& strLog )
{
    QFile file( rsp_name_ );
    file.open(QFile::WriteOnly | QFile::Append| QFile::Text );
    QTextStream SaveFile( &file );
    SaveFile << strLog << "\n";
    file.close();

    berApplet->log( strLog );
}

void CAVPDlg::clickECC_ECDSARadio()
{
    bool bVal = mECC_ECDSARadio->isChecked();

    mECCTypeCombo->clear();
    mECCTypeCombo->addItems( kECDSAType );
}

void CAVPDlg::clickECC_ECDHRadio()
{
    bool bVal = mECC_ECDHRadio->isChecked();

    mECCTypeCombo->clear();
    mECCTypeCombo->addItems( kECDHType );
}

void CAVPDlg::clickRSA_ESRadio()
{
    bool bVal = mRSA_ESRadio->isChecked();

    mRSATypeCombo->clear();
    mRSATypeCombo->addItems( kRSAESType );
}

void CAVPDlg::clickRSA_PSSRadio()
{
    bool bVal = mRSA_PSSRadio->isChecked();

    mRSATypeCombo->clear();
    mRSATypeCombo->addItems( kRSA_PSSType );
}


void CAVPDlg::clickSymRun()
{
    int ret = 0;
    berApplet->log( "SymRun\n" );

    if( mSymReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to select request file\n" );
        return;
    }

    QString strPath = mSymReqFileText->text();
    QFile reqFile( strPath );

    rsp_name_ = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();
    int nPos = 0;
    int nLen = 0;
    QString strKey;
    QString strIV;
    QString strPT;
    QString strType = mSymTypeCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );

            if( strName == "KEY" )
                strKey = strValue;
            else if( strName == "IV" )
                strIV = strValue;
            else if( strName == "PT" )
                strPT = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strKey.length() > 0 )
            {
                if( strKey.length() > 0 ) berApplet->log( QString( "Key = %1").arg( strKey ));
                if( strIV.length() > 0 ) berApplet->log( QString( "IV = %1").arg( strIV ));
                if( strPT.length() > 0 ) berApplet->log( QString( "PT = %1").arg( strPT ));

                if( strType == "MCT" )
                {
                    if( strMode == "CBC" )
                    {
                        ret = makeSymCBC_MCT( strKey, strIV, strPT );
                    }
                    else if( strMode == "ECB" )
                    {
                        ret = makeSymECB_MCT( strKey, strPT );
                    }
                    else if( strMode == "CTR" )
                    {
                        ret = makeSymCTR_MCT( strKey, strIV, strPT );
                    }
                    else if( strMode == "CFB" )
                    {
                        ret = makeSymCFB_MCT( strKey, strIV, strPT );
                    }
                    else if( strMode == "OFB" )
                    {
                        ret = makeSymOFB_MCT( strKey, strIV, strPT );
                    }
                }
                else
                    ret = makeSymData( strKey, strIV, strPT );

                if( ret != 0 )
                {
                    berApplet->warningBox( QString( "fail to run Sym:%1").arg(ret));
                    return;
                }
            }

            strKey.clear();
            strIV.clear();
            strPT.clear();
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "SymRun Done", this );
}

void CAVPDlg::clickAERun()
{
    int ret = 0;
    berApplet->log( "AERun\n" );

    if( mAEReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to select request file\n" );
        return;
    }

    QString strPath = mAEReqFileText->text();
    QFile reqFile( strPath );

    rsp_name_ = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)\n").arg( strPath ));
        return;
    }

    int nPos = 0;
    int nLen = 0;
    QString strCount;
    QString strKey;
    QString strIV;
    QString strC;
    QString strT;
    QString strAdata;
    QString strPT;

    int nKeyLen = -1;
    int nIVLen = -1;
    int nPTLen = -1;
    int nAADLen = -1;
    int nTagLen = -1;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
//        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "COUNT" )
                strCount = strValue;
            else if( strName == "Key" )
                strKey = strValue;
            else if( strName == "IV" )
                strIV = strValue;
            else if( strName == "C" )
                strC = strValue;
            else if( strName == "Adata" )
                strAdata = strValue;
            else if( strName == "PT" )
                strPT = strValue;
            else if( strName == "T" )
                strT = strValue;
            else if( strName == "KeyLen" )
                nKeyLen = strValue.toInt();
            else if( strName == "IVLen" )
                nIVLen = strValue.toInt();
            else if( strName == "PTLen" )
                nPTLen = strValue.toInt();
            else if( strName == "AADLen" )
                nAADLen = strValue.toInt();
            else if( strName == "TagLen" )
                nTagLen = strValue.toInt();
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( nKeyLen >= 0 && nIVLen >= 0 && nAADLen >= 0 && nPTLen >= 0 && nTagLen >= 0 )
            {
                berApplet->log( QString( "[KeyLen = %1]").arg( nKeyLen ));
                berApplet->log( QString( "[IVLen = %1]").arg(nIVLen));
                berApplet->log( QString( "[PTLen = %1]").arg( nPTLen ));
                berApplet->log( QString( "[AADLen = %1]").arg(nAADLen));
                berApplet->log( QString( "[TagLen = %1]").arg(nTagLen));
                berApplet->log( "" );

                nKeyLen = -1;
                nIVLen = -1;
                nAADLen = -1;
                nPTLen = -1;
            }

            if( mAETypeCombo->currentText() == "AD" )
            {
                if( strCount.length() > 0 && strKey.length() > 0 && strIV.length() > 0 && strT.length() > 0 )
                {
                    berApplet->log( QString( "COUNT = %1").arg( strCount ));
 //                   ret = makeGCM_AD( RNX_ALG_ARIA, &binKey, &binIV, &binAdata, &binC, &binT );
                    ret = makeADData( strKey, strIV, strC, strAdata, strT );

                    if( ret != 0 ) break;
                }
            }
            else
            {
                if( strCount.length() > 0 && strKey.length() > 0 && strIV.length() > 0 && nTagLen > 0 )
                {
                    berApplet->log( QString( "COUNT = %1").arg( strCount ));
 //                   ret = makeGCM_AE( RNX_ALG_ARIA, &binKey, &binIV, &binAdata, &binPT, nTagLen / 8 );
                    ret = makeAEData( strKey, strIV, strPT, strAdata, nTagLen/8 );

                    if( ret != 0 ) break;
                }
            }

            strCount.clear();
            strKey.clear();
            strIV.clear();
            strT.clear();
            strC.clear();
            strAdata.clear();
        }


        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "AERun Done", this );
}

void CAVPDlg::clickHMACRun()
{
    int ret = 0;
    berApplet->log( "HashRun\n" );

    if( mHMACReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to select request file\n" );
        return;
    }

    QString strPath = mHMACReqFileText->text();
    QFile reqFile( strPath );

    rsp_name_ = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    QString strL;
    QString strCount;
    QString strKLen;
    QString strTLen;
    QString strKey;
    QString strMsg;

    int nPos = 0;
    int nLen = 0;


    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
//        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );
            berApplet->log( QString( "Name:%1 Value:%2").arg(strName).arg(strValue));

            if( strName == "COUNT" )
                strCount = strValue;
            else if( strName == "Klen" )
                strKLen = strValue;
            else if( strName == "Tlen" )
                strTLen = strValue;
            else if( strName == "Key" )
                strKey = strValue;
            else if( strName == "Msg" )
                strMsg = strValue;
            else if( strName == "L" )
                strL = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strL.length() > 0 )
            {
                berApplet->log( QString( "L = %1").arg(strL));
                berApplet->log( "" );

                strL.clear();
            }

            if( strCount.length() > 0 && strKLen.length() > 0 && strTLen.length() > 0 && strKey.length() > 0 && strMsg.length() > 0 )
            {
                ret = makeHMACData( strCount, strKLen, strTLen, strKey, strMsg );

                if( ret != 0 )
                {
                    berApplet->warningBox( QString( "fail to run HMAC: %1").arg(ret));
                    return;
                }
            }

            strCount.clear();
            strKLen.clear();
            strTLen.clear();
            strKey.clear();
            strMsg.clear();
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "HMAC Run Done", this );
}

void CAVPDlg::clickHashRun()
{
    int ret = 0;
    berApplet->log( "HhashRun\n" );

    if( mHashReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to select request file\n" );
        return;
    }

    QString strPath = mHashReqFileText->text();
    QFile reqFile( strPath );

    rsp_name_ = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)\n").arg( strPath ));
        return;
    }

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    QString strL;
    QString strLen;
    QString strMsg;
    QString strSeed;

    int nPos = 0;
    int nLen = 0;


    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
//        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );
            berApplet->log( QString( "Name:%1 Value:%2").arg(strName).arg(strValue));

            if( strName == "L" )
                strL = strValue;
            else if( strName == "Len" )
                strLen = strValue;
            else if( strName == "Msg" )
                strMsg = strValue;
            else if( strName == "Seed" )
                strSeed = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strL.length() > 0 )
            {
                berApplet->log( QString( "L = %1").arg( strL ));
                berApplet->log( "" );
                strL.clear();
            }

            if( strMsg.length() > 0 && strLen.length() > 0 )
            {
                ret = makeHashData( strLen.toInt(), strMsg );
            }
            else if( strSeed.length() > 0 )
            {
                ret = makeHashMCT( strSeed );
            }

            strMsg.clear();
            strLen.clear();
            strSeed.clear();

            if( ret != 0 )
            {
                berApplet->warningBox( QString( "fail to run Hash : %1" ).arg(ret));
                return;
            }
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "Hash Run Done", this );
}

void CAVPDlg::clickECCRun()
{
    berApplet->log( "ECCRun\n" );
    int ret = 0;
    bool bInit = true;

    if( mECCReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to find ECDSA request file" );
        return;
    }

    QString strPath = mECCReqFileText->text();
    QFile reqFile( strPath );

    rsp_name_ = getRspFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)").arg(strPath));
        return;
    }

    int nPos = 0;
    int nLen = 0;

    QString strYX;
    QString strYY;
    QString strM;
    QString strR;
    QString strS;

    QString strQX;
    QString strQY;
    QString strRA;
    QString strRB;
    QString strKTA1X;
    QString strKTA1Y;
    QString strP;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
 //       berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "Yx" )
                strYX = strValue;
            else if( strName == "Yy" )
                strYY = strValue;
            else if( strName == "M" )
                strM = strValue;
            else if( strName == "R" )
                strR = strValue;
            else if( strName == "S" )
                strS = strValue;
            else if( strName == "Qx" )
                strQX = strValue;
            else if( strName == "Qy" )
                strQY = strValue;
            else if( strName == "rA" )
                strRA = strValue;
            else if( strName == "rB" )
                strRB = strValue;
            else if( strName == "KTA1x" )
                strKTA1X = strValue;
            else if( strName == "KTA1y" )
                strKTA1Y = strValue;
            else if( strName == "P-256" )
                strP = "prime256v1";
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "KPG" )
            {
                if( bInit == true )
                {
                    berApplet->log( "[P-256]" );
                    bInit = false;
                }

                ret = makeECDSA_KPG( 10 );
                if( ret != 0 )
                {
                    berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                    return;
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "PKV" )
            {
                if( bInit == true )
                {
                    berApplet->log( "# ECDSA" );
                    berApplet->log( "" );
                    bInit = false;
                }

                if( strYX.length() > 0 && strYY.length() > 0 )
                {
                    ret = makeECDSA_PKV( strYX, strYY );
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "SGT" )
            {
                if( bInit == true )
                {
                    berApplet->log( "[P-256, SHA-256]" );
                    bInit = false;
                }

                if( strM.length() > 0 )
                {
                    ret = makeECDSA_SGT( strM );
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mECC_ECDSARadio->isChecked() && mECCTypeCombo->currentText() == "SVT" )
            {
                if( bInit == true )
                {
                    berApplet->log( "# ECDSA" );
                    berApplet->log( "" );
                    berApplet->log( "[P-256, SHA-256]" );
                    bInit = false;
                }

                if( strM.length() > 0 && strYX.length() > 0 && strYY.length() > 0 && strR.length() > 0 && strS.length() > 0 )
                {
                    ret = makeECDSA_SVT( strM, strYX, strYY, strR, strS );
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "KPG" )
            {
                if( bInit )
                {
                    berApplet->log( "[P-256]" );
                    berApplet->log( "" );
                    bInit = false;
                }

                ret = makeECDH_KPG( 15 );
                if( ret != 0 )
                {
                    berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                    return;
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "PKV" )
            {
                if( bInit )
                {
                    berApplet->log( "[P-256]" );
                    bInit = false;
                }

                if( strQX.length() > 0 && strQY.length() > 0 )
                {
                    ret = makeECDH_PKV( strQX, strQY );

                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mECC_ECDHRadio->isChecked() && mECCTypeCombo->currentText() == "KAKAT" )
            {
                if( bInit )
                {
                    berApplet->log( "[P-256]" );
                    bInit = false;
                }

                if( strRA.length() > 0 && strRB.length() > 0 && strKTA1X.length() > 0 && strKTA1Y.length() > 0 )
                {
                    ret = makeECDH_KAKAT( strRA, strRB, strKTA1X, strKTA1Y );

                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run ECC: %1").arg(ret));
                        return;
                    }
                }
            }

            strM.clear();
            strYX.clear();
            strYY.clear();
            strR.clear();
            strS.clear();

            strQX.clear();
            strQY.clear();
            strRA.clear();
            strRB.clear();
            strKTA1X.clear();
            strKTA1Y.clear();
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "ECC Run Done", this );
}

void CAVPDlg::clickRSARun()
{
    int ret = 0;
    bool bInit = true;
    berApplet->log( "Run RSA" );

    if( mRSAReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to find RSA PSS request file" );
        return;
    }

    QString strPath = mRSAReqFileText->text();
    QFile reqFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)").arg(strPath));
        return;
    }

    rsp_name_ = getRspFile( strPath );

    int nPos = 0;
    int nLen = 0;

    int nKeyLen = -1;
    int nE = 65537;

    QString strM;
    QString strS;
    QString strN;
    QString strE;
    QString strHash;
    QString strC;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
 //       berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            getNameValue( strLine, strName, strValue );

            if( strName == "|n|" || strName == "mod" )
                nKeyLen = strValue.toInt();
            else if( strName == "n" )
                strN = strValue;
            else if( strName == "M" )
                strM = strValue;
            else if( strName == "S" )
                strS = strValue;
            else if( strName == "e" || strName == "v" )
                strE = strValue;
            else if( strName == "C" )
                strC = strValue;
            else if( strName == "HashAlg" || strName == "SHAAlg" )
                strHash = strValue;
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "KPG" )
            {
                if( nKeyLen > 0 )
                {
                    if( bInit == true )
                    {
                        berApplet->log( QString( "|n| = %1").arg(nKeyLen));
                        berApplet->log( "" );
                        bInit = false;
                    }

                    ret = makeRSA_PSS_KPG( nKeyLen, 10 );
                    nKeyLen = -1;
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run RSA : %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "SGT" )
            {
                if( strM.length() > 0 && strE.length() > 0 && strHash.length() > 0 )
                {
                    ret = makeRSA_PSS_SGT( strE.toInt(), strHash, strM );
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run RSA : %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mRSA_PSSRadio->isChecked() && mRSATypeCombo->currentText() == "SVT" )
            {
                if( strS.length() > 0 && strM.length() > 0 )
                {
                    ret = makeRSA_PSS_SVT( strE, strN, strHash, strM, strS );
                    if( ret != 0 )
                    {
                        berApplet->warningBox( QString( "fail to run RSA : %1").arg(ret));
                        return;
                    }
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "DET" )
            {
                int nKeyIndex = 0;
                const QString strPri = "";

                if( bInit == true )
                {
                    berApplet->log( QString( "|n| = %1").arg(nKeyLen));
                    berApplet->log( QString( "n = %1").arg( strN ));
                    berApplet->log( "e = 10001" );
                    berApplet->log( "" );
                    bInit = false;
                }

                if( strC.length() > 0 && strHash.length() > 0 )
                {
                    berApplet->log( QString( "SHAAlg = %1").arg(strHash));

                    ret = makeRSA_ES_DET( strPri, strC );

                    if( ret != 0 ) return;
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "ENT" )
            {
                const QString strPub = "";

                if( strN.length() > 0 && nE > 0 )
                {
                    berApplet->log( QString("|n| = %1").arg( strN.length()/2 ));
                    berApplet->log( QString( "n = %1").arg( strN));
                    berApplet->log( QString( "e = %1").arg(nE));
                    berApplet->log( "" );
                    berApplet->log( "hash = SHA256" );
                    berApplet->log( "" );
                }

                if( strM.length() > 0 )
                {
                    ret = makeRSA_ES_ENT( strPub, strM );

                    if( ret != 0 ) return;
                }
            }
            else if( mRSA_ESRadio->isChecked() && mRSATypeCombo->currentText() == "KGT" )
            {
                if( nKeyLen > 0 && nE > 0 )
                {
                    if( bInit == true )
                    {
                        berApplet->log( QString( "|n| = %1").arg(nKeyLen));
                        berApplet->log( QString( "e = %1").arg(nE));
                        berApplet->log( "" );
                        bInit = false;
                    }

                    ret = makeRSA_ES_KGT( nKeyLen, nE, 10 );
                    nKeyLen = -1;
                    if( ret != 0 ) return;
                }
            }

            strS.clear();
            strM.clear();
            strN.clear();
            strC.clear();

            if( mRSA_ESRadio->isChecked() ) strHash.clear();
        }


        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "RSA Run Done", this );
}

void CAVPDlg::clickDRBGTest()
{
    BIN binRand1 = {0,0};
    BIN binRand2 = {0,0};

    JS_PKI_DRBGTest( &binRand1, &binRand2 );

    berApplet->log( QString( "Rand1: %1" ).arg(getHexString(binRand1.pVal, binRand1.nLen)));
    berApplet->log( QString( "Rand2: %1").arg(getHexString(binRand2.pVal, binRand2.nLen)));

    JS_BIN_reset( &binRand1 );
    JS_BIN_reset( &binRand2 );
}

void CAVPDlg::clickDRBGRun()
{
    berApplet->log( "DRBGRun\n" );
    int ret = 0;

    if( mDRBGReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to find DRBG request file" );
        return;
    }

    QString strPath = mDRBGReqFileText->text();
    QFile reqFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)").arg(strPath));
        return;
    }

    rsp_name_ = getRspFile( strPath );

    int nPos = 0;
    int nLen = 0;

    QString strPredictionResistance;
    int nEntropyInputLen = -1;
    int nNonceLen = -1;
    int nPersonalizationStringLen = -1;
    int nAdditionalInputLen = -1;
    int nReturnedBitsLen = -1;

    int nCount = -1;
    QString strEntropyInput;
    QString strNonce;
    QString strPersonalizationString;
    QString strEntropyInputReseed;
    QString strAdditionalInputReseed;
    QString strAdditionalInput1;
    QString strAdditionalInput2;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
//        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "PredictionResistance" )
                strPredictionResistance = strValue;
            else if( strName == "EntropyInputLen" )
                nEntropyInputLen = strValue.toInt() / 8;
            else if( strName == "NonceLen" )
                nNonceLen = strValue.toInt() / 8;
            else if( strName == "PersonalizationStringLen" )
                nPersonalizationStringLen = strValue.toInt() / 8;
            else if( strName == "AdditionalInputLen" )
                nAdditionalInputLen = strValue.toInt() / 8;
            else if( strName == "ReturnedBitsLen" )
                nReturnedBitsLen = strValue.toInt() / 8;
            else if( strName == "COUNT" )
                nCount = strValue.toInt();
            else if( strName == "EntropyInput" )
                strEntropyInput = strValue;
            else if( strName == "Nonce" )
                strNonce = strValue;
            else if( strName == "PersonalizationString" )
                strPersonalizationString = strValue;
            else if( strName == "EntropyInputReseed" )
                strEntropyInputReseed = strValue;
            else if( strName == "AdditionalInputReseed" )
                strAdditionalInputReseed = strValue;
            else if( strName == "AdditionalInput" )
            {
                if( strAdditionalInput1.isEmpty() )
                    strAdditionalInput1 = strValue;
                else
                    strAdditionalInput2 = strValue;
            }
        }

        if( nLen == 0 || strNext.isNull() )
        {
            if( strPredictionResistance.length() > 0 &&
                    nEntropyInputLen >= 0 &&
                    nNonceLen >= 0 &&
                    nPersonalizationStringLen >= 0 &&
                    nAdditionalInputLen >= 0 &&
                    nReturnedBitsLen >= 0 )
            {
                berApplet->log( "[ARIA-128 use DF]" );
                berApplet->log( QString( "[PredictionResistance = %1]" ).arg( strPredictionResistance ));
                berApplet->log( QString( "[EntropyInputLen = %1]" ).arg( nEntropyInputLen * 8 ));
                berApplet->log( QString( "[NonceLen = %1]" ).arg( nNonceLen * 8));
                berApplet->log( QString( "[PersonalizationStringLen = %1]" ).arg( nPersonalizationStringLen * 8));
                berApplet->log( QString( "[AdditionalInputLen = %1]").arg( nAdditionalInputLen * 8 ));
                berApplet->log( QString( "[ReturnedBitsLen = %1]").arg( nReturnedBitsLen * 8 ));
                berApplet->log( "" );

                strPredictionResistance.clear();
            }

            if( nCount >= 0 && strEntropyInput.length() == (nEntropyInputLen * 2) &&
                    strNonce.length() == (nNonceLen * 2) &&
                    strPersonalizationString.length() == (nPersonalizationStringLen * 2) &&
                    strEntropyInputReseed.length() == (nEntropyInputLen * 2) &&
                    strAdditionalInputReseed.length() == (nAdditionalInputLen * 2) &&
                    strAdditionalInput1.length() == (nAdditionalInputLen * 2) &&
                    strAdditionalInput2.length() == (nAdditionalInputLen * 2) )
            {
                berApplet->log( QString( "COUNT = %1").arg( nCount ));

                ret = makeDRBG( nReturnedBitsLen,
                                mDRBGAlgCombo->currentText(),
                                mDRBGUseDFCheck->isChecked(),
                                mDRBGUsePRCheck->isChecked(),
                                strEntropyInput,
                                strNonce,
                                strPersonalizationString,
                                strEntropyInputReseed,
                                strAdditionalInputReseed,
                                strAdditionalInput1,
                                strAdditionalInput2 );



                if( ret != 0 ) return;
            }

            strEntropyInput.clear();
            strNonce.clear();
            strPersonalizationString.clear();
            strEntropyInputReseed.clear();
            strAdditionalInputReseed.clear();
            strAdditionalInput1.clear();
            strAdditionalInput2.clear();
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "DRBG Run Done", this );
}

void CAVPDlg::clickPBKDFRun()
{
    berApplet->log( "PBKDFRun\n" );
    int ret = 0;

    if( mPBKDFReqFileText->text().length() < 1 )
    {
        berApplet->elog( "You have to find PBKDF request file" );
        return;
    }

    QString strPath = mPBKDFReqFileText->text();
    QFile reqFile( strPath );

    if( !reqFile.open( QIODevice::ReadOnly | QIODevice::Text ))
    {
        berApplet->elog( QString( "fail to open file(%1)").arg(strPath));
        return;
    }

    rsp_name_ = getRspFile( strPath );

    int nPos = 0;
    int nLen = 0;
    int nCount = -1;
    int nIteration = -1;
    int nKLen = -1;

    QString strPasswd;
    QString strSalt;
    QString strPRF;

    QTextStream in( &reqFile );
    QString strLine = in.readLine();

    while( strLine.isNull() == false )
    {
        QString strName;
        QString strValue;
        QString strNext = in.readLine();

        nLen = strLine.length();
//        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

        if( nLen > 0 )
        {
            strLine.remove( '[' );
            strLine.remove( ']' );

            getNameValue( strLine, strName, strValue );

            if( strName == "COUNT" )
                nCount = strValue.toInt();
            else if( strName == "Password" )
                strPasswd = strValue;
            else if( strName == "Salt" )
                strSalt = strValue;
            else if( strName == "KLen" )
                nKLen = strValue.toInt();
            else if( strName == "Iteration" )
                nIteration = strValue.toInt();
            else if( strName == "PRF" )
                strPRF = strValue;
        }


        if( nLen == 0 || strNext.isNull() )
        {
            if( strPRF.length() > 0 && nIteration > 0 )
            {
                berApplet->log( QString( "[PRF = %1]" ).arg( strPRF ));
                berApplet->log( QString( "[Iteration = %1]" ).arg( nIteration ));
                berApplet->log( "" );

                strPRF.clear();
            }

            if( nIteration > 0 && nCount >= 0 && strPasswd.length() > 0 && strSalt.length() > 0 && nKLen > 0 )
            {
                berApplet->log( QString( "COUNT = %1" ).arg( nCount ));
                ret = makePBKDF( nIteration, strPasswd, strSalt, nKLen );

                nKLen = -1;
                nCount = -1;
                if( ret != 0 )
                {
                    berApplet->warningBox( QString( "fail to run PBKDF: %1").arg(ret), this );
                    return;
                }
            }

            strPasswd.clear();
            strSalt.clear();
        }

        strLine = strNext;
        nPos++;
    }

    berApplet->messageBox( "PBKDF Run Done", this );
}

void CAVPDlg::clickSymFind()
{
    QString strPath = mSymReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mSymReqFileText->setText( strFile );
}

void CAVPDlg::clickAEFind()
{
    QString strPath = mAEReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mAEReqFileText->setText( strFile );
}

void CAVPDlg::clickHashFind()
{
    QString strPath = mHashReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mHashReqFileText->setText( strFile );
}

void CAVPDlg::clickHMACFind()
{
    QString strPath = mHMACReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mHMACReqFileText->setText( strFile );
}

void CAVPDlg::clickECCFind()
{
    QString strPath = mECCReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mECCReqFileText->setText( strFile );
}

void CAVPDlg::clickRSAFind()
{
    QString strPath = mRSAReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mRSAReqFileText->setText( strFile );
}

void CAVPDlg::clickDRBGFind()
{
    QString strPath = mDRBGReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mDRBGReqFileText->setText( strFile );
}

void CAVPDlg::clickPBKDFFind()
{
    QString strPath = mPBKDFReqFileText->text();

    QString strFile = findFile( this, JS_FILE_TYPE_REQ, strPath );
    if( strFile.length() > 0 )
        mPBKDFReqFileText->setText( strFile );
}

void CAVPDlg::MCTKeyChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTKeyLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTIVChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTIVLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTPTChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTPTLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTCTChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTCTLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTLastKeyChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTLastKeyLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTLastIVChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTLastIVLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTLastPTChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTLastPTLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTLastCTChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mSymMCTLastCTLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTSHA256SeedChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mHashMCTSeedLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTSHA256FirstMDChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mHashMCTFirstMDLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::MCTSHA256LastMDChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mHashMCTLastMDLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2EntropyInputChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2EntropyInputLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2NonceChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2NonceLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2PersonalStringChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2PersonalStringLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2EntropyInputReseedChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2EntropyInputReseedLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2AdditionalInputReseedChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2AdditionalInputReseedLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2AdditionalInputChanged( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2AdditionalInputLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2AdditionalInput2Changed( const QString& text )
{
    int nLen = text.length() / 2;
    mDRBG2AdditionalInput2LenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::DRBG2ReturnedBitsChanged()
{
    int nLen = mDRBG2ReturnedBitsText->toPlainText().length() / 2;
    mDRBG2ReturnedBitsLenText->setText( QString("%1").arg(nLen));
}

void CAVPDlg::clickSymMCTRun()
{
    int nRet = 0;

    QString strKey = mSymMCTKeyText->text();
    QString strIV = mSymMCTIVText->text();
    QString strPT = mSymMCTPTText->text();

    if( strKey.length() < 1 )
    {
        berApplet->elog( "You have to insert KEY" );
        return;
    }

    if( strPT.length() < 1 )
    {
        berApplet->elog( "You have to insert PT" );
        return;
    }

    rsp_name_ = QString( "%1_%2_%d_MCT.req")
            .arg( mSymMCTAlgCombo->currentText() )
            .arg( mSymMCTModeCombo->currentText() )
            .arg( strKey.length() / 2 );


    mSymMCTCTText->clear();
    mSymMCTLastKeyText->clear();
    mSymMCTLastIVText->clear();
    mSymMCTLastPTText->clear();
    mSymMCTLastCTText->clear();

    if( mSymMCTModeCombo->currentText() == "ECB" )
        nRet = makeSymECB_MCT( strKey, strPT, true );
    else if( mSymMCTModeCombo->currentText() == "CBC" )
        nRet = makeSymCBC_MCT( strKey, strIV, strPT, true );
    else if( mSymMCTModeCombo->currentText() == "CTR" )
        nRet = makeSymCTR_MCT( strKey, strIV, strPT, true );
    else if( mSymMCTModeCombo->currentText() == "CFB" )
        nRet = makeSymCFB_MCT( strKey, strIV, strPT, true );
    else if( mSymMCTModeCombo->currentText() == "OFB" )
        nRet = makeSymOFB_MCT( strKey, strIV, strPT, true );

    if( nRet == 0 )
        berApplet->messageBox( "Sym MCT Done", this );
    else
        berApplet->warningBox( QString( "fail to run Sym MCT: %1").arg(nRet), this);
}

void CAVPDlg::clickSymMCTClear()
{
    mSymMCTKeyText->clear();
    mSymMCTIVText->clear();
    mSymMCTPTText->clear();
    mSymMCTCTText->clear();
    mSymMCTLastKeyText->clear();
    mSymMCTLastIVText->clear();
    mSymMCTLastPTText->clear();
    mSymMCTLastCTText->clear();
}

void CAVPDlg::clickHashMCTRun()
{
    int ret = 0;
    QString strPath;

    QString strSeed = mHashMCTSeedText->text();

    if( strSeed.length() < 1 )
    {
        berApplet->elog( "You have to insert Seed" );
        return;
    }

    rsp_name_ = QString( "SHA256_MCT.req" );

    ret = makeHashMCT( strSeed, true );

    if( ret == 0 )
        berApplet->messageBox( "Hash MCT Done", this );
    else
        berApplet->warningBox( QString( "fail to run hash MCT: %1").arg(ret), this);
}

void CAVPDlg::clickHashMCTClear()
{
    mHashMCTSeedText->clear();
    mHashMCTFirstMDText->clear();
    mHashMCTLastMDText->clear();
    mHashMCTCountText->clear();
}

void CAVPDlg::clickDRBG2Clear()
{
    mDRBG2EntropyInputText->clear();
    mDRBG2NonceText->clear();
    mDRBG2PersonalStringText->clear();
    mDRBG2EntropyInputReseedText->clear();
    mDRBG2AdditionalInputReseedText->clear();
    mDRBG2AdditionalInputText->clear();
    mDRBG2AdditionalInput2Text->clear();
    mDRBG2ReturnedBitsText->clear();
}

void CAVPDlg::clickDRBG2Run()
{
    int ret = 0;
    int nRandLen = mDRBG2RandLenText->text().toInt() / 8;

    QString strEntroypInput = mDRBG2EntropyInputText->text();
    QString strNonce = mDRBG2NonceText->text();
    QString strPersonalString = mDRBG2PersonalStringText->text();
    QString strEntropyInputReseed = mDRBG2EntropyInputReseedText->text();
    QString strAdditionalInputReseed = mDRBG2AdditionalInputReseedText->text();
    QString strAdditionalInput = mDRBG2AdditionalInputText->text();
    QString strAdditionalInput2 = mDRBG2AdditionalInput2Text->text();

    ret = makeDRBG( nRandLen,
                    mDRBG2AlgCombo->currentText(),
                    mDRBG2UseDFCheck->isChecked(),
                    mDRBG2UsePRCheck->isChecked(),
                    strEntroypInput,
                    strNonce,
                    strPersonalString,
                    strEntropyInputReseed,
                    strAdditionalInputReseed,
                    strAdditionalInput,
                    strAdditionalInput2,
                    true );

    if( ret == 0 )
        berApplet->messageBox( QString( "DRBG2 Run Success" ), this );
    else
        berApplet->warningBox( QString( "DRBG2 Run fail: %1").arg(ret), this );

}

int CAVPDlg::makeSymData( const QString strKey, const QString strIV, const QString strPT )
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binPT = {0,0};
    BIN binEnc = {0,0};

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
    JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT );

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey.nLen );

    ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT, &binIV, &binKey, &binEnc );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to encrypt:%1").arg(ret));
        goto end;
    }

    berApplet->log( QString( "CT = %1").arg( getHexString(binEnc.pVal, binEnc.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binEnc );

    return ret;
}

int CAVPDlg::makeSymCBC_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo )
{
    int ret = 0;
    int i = 0;
    int j = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[100 + 1];
    BIN binCT[100 + 1];

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    if( strKey.length() > 0 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey[0] );

    if( strIV.length() > 0 )
        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV[0] );

    if( strPT.length() > 0 )
        JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT[0] );

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey[0].nLen );
    berApplet->log( QString("Symmetric Alg: %1").arg( strSymAlg ));

    for( i = 0; i < 100; i++ )
    {
        if( bInfo )
        {
            mSymMCTCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mSymMCTLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mSymMCTLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mSymMCTLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        berApplet->log( QString("COUNT = %1").arg(i));
        berApplet->log( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        berApplet->log( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        berApplet->log( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        for( j = 0; j < 1000; j++ )
        {
            JS_BIN_reset( &binCT[j] );
            ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT[j], &binIV[i], &binKey[i], &binCT[j] );
            if( ret != 0 ) goto end;

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        j = j - 1;

        if( bInfo )
        {
            if( i == 0 )
            {
                mSymMCTCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mSymMCTLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        berApplet->log( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        berApplet->log( "" );

        if( (strKey.length()/2) == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( (strKey.length()/2) == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( (strKey.length()/2) == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);
    }

end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i]);
        JS_BIN_reset( &binIV[i]);
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }
}

int CAVPDlg::makeSymECB_MCT( const QString strKey, const QString strPT, bool bInfo )
{
    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100 + 1];
    BIN binPT[1000 + 1];
    BIN binCT[1000 + 1];

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey[0] );
    JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT[0] );

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey[0].nLen );
    berApplet->log( QString("Symmetric Alg: %1").arg( strSymAlg ));


    for( i = 0; i < 100; i++ )
    {
        berApplet->log( QString("COUNT = %1").arg(i));
        berApplet->log( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        berApplet->log( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        if( bInfo )
        {
            mSymMCTCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mSymMCTLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mSymMCTLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        for( j = 0; j < 1000; j++ )
        {
            ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT[j], NULL, &binKey[i], &binCT[j] );
            if( ret != 0 ) goto end;

            JS_BIN_reset( &binPT[j+1] );
            JS_BIN_copy( &binPT[j+1], &binCT[j] );
        }

        j = j - 1;

        if( bInfo )
        {
            if( i == 0 )
            {
                mSymMCTCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mSymMCTLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        berApplet->log( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        berApplet->log( "" );

        if( (strKey.length()/2) == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( (strKey.length()/2) == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( (strKey.length()/2) == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j]);
    }


 end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymCTR_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo )
{
    int i = 0;
    int j = 0;
    int ret = 0;

    BIN binKey[100+1];
    BIN binCTR = {0,0};
    BIN binPT[1000+1];
    BIN binCT[1000+1];

    memset( &binKey, 0x00, sizeof(BIN) * 101 );
    memset( &binPT, 0x00, sizeof(BIN) * 1001 );
    memset( &binCT, 0x00, sizeof(BIN) * 1001 );

    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey[0] );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binCTR );
    JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT[0] );

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey[0].nLen );
    berApplet->log( QString("Symmetric Alg: %1").arg( strSymAlg ));

    for( i = 0; i < 100; i++ )
    {
        if( bInfo )
        {
            mSymMCTCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mSymMCTLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mSymMCTLastIVText->setText(getHexString( binCTR.pVal, binCTR.nLen ));
                mSymMCTLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        berApplet->log( QString("COUNT = %1").arg(i));
        berApplet->log( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        berApplet->log( QString("CTR = %1").arg( getHexString(binCTR.pVal, binCTR.nLen)));
        berApplet->log( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        for( j = 0; j < 1000; j++ )
        {
            ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT[j], &binCTR, &binKey[i], &binCT[j] );
            if( ret != 0 ) goto end;

            JS_BIN_INC( &binCTR );

            JS_BIN_reset( &binPT[j+1] );
            JS_BIN_copy( &binPT[j+1], &binCT[j] );
        }

        j = j - 1;

        if( bInfo )
        {
            if( i == 0 )
            {
                mSymMCTCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mSymMCTLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        berApplet->log( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        berApplet->log( "" );

        if( (strKey.length()/2) == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( (strKey.length()/2) == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( (strKey.length()/2) == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j]);
    }

 end :
    JS_BIN_reset( &binCTR );

    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i] );
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymCFB_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo )
{
    int ret = 0;
    int i = 0;
    int j = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[100 + 1];
    BIN binCT[100 + 1];

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    if( strKey.length() > 0 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey[0] );

    if( strIV.length() > 0 )
        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV[0] );

    if( strPT.length() > 0 )
        JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT[0] );

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey[0].nLen );
    berApplet->log( QString("Symmetric Alg: %1").arg( strSymAlg ));

    for( i = 0; i < 100; i++ )
    {
        if( bInfo )
        {
            mSymMCTCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mSymMCTLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mSymMCTLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mSymMCTLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        berApplet->log( QString("COUNT = %1").arg(i));
        berApplet->log( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        berApplet->log( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        berApplet->log( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        for( j = 0; j < 1000; j++ )
        {
            JS_BIN_reset( &binCT[j] );
            ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT[j], &binIV[i], &binKey[i], &binCT[j] );
            if( ret != 0 ) goto end;

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        j = j - 1;

        if( bInfo )
        {
            if( i == 0 )
            {
                mSymMCTCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mSymMCTLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        berApplet->log( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        berApplet->log( "" );

        if( (strKey.length()/2) == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( (strKey.length()/2) == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( (strKey.length()/2) == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);
    }

end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i]);
        JS_BIN_reset( &binIV[i]);
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeSymOFB_MCT( const QString strKey, const QString strIV, const QString strPT, bool bInfo )
{
    int ret = 0;
    int i = 0;
    int j = 0;

    BIN binKey[100 + 1];
    BIN binIV[100 + 1];
    BIN binPT[100 + 1];
    BIN binCT[100 + 1];

    QString strAlg = mSymAlgCombo->currentText();
    QString strMode = mSymModeCombo->currentText();

    if( strKey.length() > 0 )
        JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey[0] );

    if( strIV.length() > 0 )
        JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV[0] );

    if( strPT.length() > 0 )
        JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT[0] );

    QString strSymAlg = getSymAlg( strAlg, strMode, binKey[0].nLen );
    berApplet->log( QString("Symmetric Alg: %1").arg( strSymAlg ));

    for( i = 0; i < 100; i++ )
    {
        if( bInfo )
        {
            mSymMCTCountText->setText( QString("%1").arg(i) );

            if( i == 99 )
            {
                mSymMCTLastKeyText->setText( getHexString(binKey[i].pVal, binKey[i].nLen));
                mSymMCTLastIVText->setText(getHexString(binIV[i].pVal, binIV[i].nLen));
                mSymMCTLastPTText->setText( getHexString(binPT[0].pVal, binPT[0].nLen));
            }
        }

        berApplet->log( QString("COUNT = %1").arg(i));
        berApplet->log( QString("KEY = %1").arg( getHexString(binKey[i].pVal, binKey[i].nLen)));
        berApplet->log( QString("IV = %1").arg( getHexString(binIV[i].pVal, binIV[i].nLen)));
        berApplet->log( QString("PT = %1").arg(getHexString(binPT[0].pVal, binPT[0].nLen)));

        for( j = 0; j < 1000; j++ )
        {
            JS_BIN_reset( &binCT[j] );
            ret = JS_PKI_encryptData( strSymAlg.toStdString().c_str(), 0, &binPT[j], &binIV[i], &binKey[i], &binCT[j] );
            if( ret != 0 ) goto end;

            if( j == 0 )
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binIV[i] );
            }
            else
            {
                JS_BIN_reset( &binPT[j+1] );
                JS_BIN_copy( &binPT[j+1], &binCT[j-1] );
            }
        }

        j = j - 1;

        if( bInfo )
        {
            if( i == 0 )
            {
                mSymMCTCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
            else if( i == 99 )
            {
                mSymMCTLastCTText->setText( getHexString(binCT[j].pVal, binCT[j].nLen) );
            }
        }

        berApplet->log( QString("CT = %1").arg(getHexString(binCT[j].pVal, binCT[j].nLen)));
        berApplet->log( "" );

        if( (strKey.length()/2) == 16 )
        {
            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binCT[j] );
        }
        else if( (strKey.length()/2) == 24 )
        {
            BIN binTmp = {0,0};

            JS_BIN_set( &binTmp, &binCT[j-1].pVal[8], 8 );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }
        else if( (strKey.length()/2) == 32 )
        {
            BIN binTmp = {0,0};

            JS_BIN_copy( &binTmp, &binCT[j-1] );
            JS_BIN_appendBin( &binTmp, &binCT[j] );

            JS_BIN_reset( &binKey[i+1] );
            JS_BIN_XOR( &binKey[i+1], &binKey[i], &binTmp );
            JS_BIN_reset( &binTmp );
        }

        JS_BIN_reset( &binIV[i+1] );
        JS_BIN_copy( &binIV[i+1], &binCT[j] );
        JS_BIN_reset( &binPT[0] );
        JS_BIN_copy( &binPT[0], &binCT[j-1]);
    }

end :
    for( int i = 0; i < 101; i++ )
    {
        JS_BIN_reset( &binKey[i]);
        JS_BIN_reset( &binIV[i]);
    }

    for( int i = 0; i < 1001; i++ )
    {
        JS_BIN_reset( &binPT[i] );
        JS_BIN_reset( &binCT[i] );
    }

    return ret;
}

int CAVPDlg::makeAEData( const QString strKey, const QString strIV, const QString strPT, const QString strAAD, int nTagLen )
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binPT = {0,0};
    BIN binAAD = {0,0};
    BIN binTag = {0,0};
    BIN binEnc = {0,0};

    QString strMode = mAEModeCombo->currentText();
    QString strAlg = mAEAlgCombo->currentText();
    QString strEncAlg;


    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
    JS_BIN_decodeHex( strPT.toStdString().c_str(), &binPT );
    JS_BIN_decodeHex( strAAD.toStdString().c_str(), &binAAD );

    berApplet->log( QString( "Key = %1").arg(strKey ));
    berApplet->log( QString( "IV = %1").arg(strIV));
    berApplet->log( QString( "PT = %1").arg(strPT));
    berApplet->log( QString( "Adata = %1").arg(strAAD));

    strEncAlg = getSymAlg( strAlg, strMode, binKey.nLen );

    if( strMode == "GCM" )
    {
        ret = JS_PKI_encrytGCM( strEncAlg.toStdString().c_str(), &binPT, &binKey, &binIV, &binAAD, &binTag, &binEnc );
    }
    else
    {
        ret = JS_PKI_encryptCCM( strEncAlg.toStdString().c_str(), &binPT, &binKey, &binIV, &binAAD, &binTag, &binEnc );
    }

    if( ret != 0 ) goto end;

    berApplet->log( QString( "C = %1").arg(getHexString( binEnc.pVal, binEnc.nLen)));
    berApplet->log( QString( "T = %1").arg(getHexString( binTag.pVal, binTag.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );
    JS_BIN_reset( &binEnc );

    return ret;
}

int CAVPDlg::makeADData( const QString strKey, const QString strIV, const QString strCT, const QString strAAD, const QString strTag )
{
    int ret = 0;
    BIN binKey = {0,0};
    BIN binIV = {0,0};
    BIN binCT = {0,0};
    BIN binAAD = {0,0};
    BIN binTag = {0,0};
    BIN binPT = {0,0};

    QString strMode = mAEModeCombo->currentText();
    QString strAlg = mAEAlgCombo->currentText();
    QString strEncAlg;


    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strIV.toStdString().c_str(), &binIV );
    JS_BIN_decodeHex( strCT.toStdString().c_str(), &binCT );
    JS_BIN_decodeHex( strAAD.toStdString().c_str(), &binAAD );
    JS_BIN_decodeHex( strTag.toStdString().c_str(), &binTag );

    berApplet->log( QString( "Key = %1").arg(strKey ));
    berApplet->log( QString( "IV = %1").arg(strIV));
    berApplet->log( QString( "CT = %1").arg(strCT));
    berApplet->log( QString( "Adata = %1").arg(strAAD));

    strEncAlg = getSymAlg( strAlg, strMode, binKey.nLen );

    if( strMode == "GCM" )
    {
        ret = JS_PKI_decryptGCM( strEncAlg.toStdString().c_str(), &binCT, &binKey, &binIV, &binAAD, &binTag, &binPT );
    }
    else
    {
        ret = JS_PKI_decryptCCM( strEncAlg.toStdString().c_str(), &binCT, &binKey, &binIV, &binAAD, &binTag, &binPT );
    }

    if( ret == 0 )
    {
        berApplet->log( QString( "PT = %1").arg( getHexString(binPT.pVal, binPT.nLen)));
    }
    else
    {
        berApplet->log( "Invalid" );
    }

    berApplet->log( "" );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPT );
    JS_BIN_reset( &binAAD );
    JS_BIN_reset( &binTag );
    JS_BIN_reset( &binCT );

    return ret;
}

int CAVPDlg::makeHashData( int nLen, const QString strVal )
{
    int ret = 0;
    BIN binVal = {0,0};
    BIN binHash = {0,0};

    QString strAlg = mHashAlgCombo->currentText();

    JS_BIN_decodeHex( strVal.toStdString().c_str(), &binVal );

    ret = JS_PKI_genHash( strAlg.toStdString().c_str(), &binVal, &binHash );
    if( ret != 0 ) goto end;

    berApplet->log( QString( "Len = %1").arg( nLen ));
    berApplet->log( QString( "Msg = %1").arg( strVal ));
    berApplet->log( QString( "MD = %1").arg(getHexString( binHash.pVal, binHash.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binHash );

    return ret;
}

int CAVPDlg::makeHashMCT( const QString strSeed, bool bInfo )
{
    int ret = 0;
    BIN binMD[1003 + 1];
    BIN binM[1003 + 1];
    BIN binSeed = {0,0};

    berApplet->log( QString("Seed = %1").arg(strSeed));
    berApplet->log( "" );

    QString strAlg = mHashAlgCombo->currentText();

    memset( &binMD, 0x00, sizeof(BIN) * 1004 );
    memset( &binM, 0x00, sizeof(BIN) * 1004 );

    JS_BIN_decodeHex( strSeed.toStdString().c_str(), &binSeed );

    for( int j = 0; j < 100; j++ )
    {
        JS_BIN_reset( &binMD[0] );
        JS_BIN_reset( &binMD[1] );
        JS_BIN_reset( &binMD[2] );

        JS_BIN_copy( &binMD[0], &binSeed );
        JS_BIN_copy( &binMD[1], &binSeed );
        JS_BIN_copy( &binMD[2], &binSeed );

        if( bInfo ) mHashMCTCountText->setText( QString("%1").arg(j));

        for( int i = 3; i < 1003; i++ )
        {
            JS_BIN_reset( &binM[i] );
            JS_BIN_appendBin( &binM[i], &binMD[i-3] );
            JS_BIN_appendBin( &binM[i], &binMD[i-2] );
            JS_BIN_appendBin( &binM[i], &binMD[i-1] );

            JS_BIN_reset( &binMD[i] );
            ret = JS_PKI_genHash( strAlg.toStdString().c_str(), &binM[i], &binMD[i] );
            if( ret != 0 ) goto end;
        }

        JS_BIN_reset( &binMD[j] );
        JS_BIN_reset( &binSeed );
        JS_BIN_copy( &binSeed, &binMD[1002] );
        JS_BIN_copy( &binMD[j], &binSeed );

        if( bInfo )
        {
            if( j == 0 )
                mHashMCTFirstMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));

            if( j == 99 )
                mHashMCTFirstMDText->setText( getHexString(binMD[j].pVal, binMD[j].nLen));
        }

        berApplet->log( QString( "COUNT = %1").arg(j));
        berApplet->log( QString( "MD = %1").arg(getHexString(binMD[j].pVal, binMD[j].nLen)));
        berApplet->log( "" );
    }

end :
    for( int i = 0; i < 1004; i++ )
    {
        JS_BIN_reset( &binMD[i] );
        JS_BIN_reset( &binM[i] );
    }

    JS_BIN_reset( &binSeed );
    return ret;
}

int CAVPDlg::makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const QString strKey, const QString strMsg )
{
    int ret = 0;

    BIN binKey = {0,0};
    BIN binMsg = {0,0};
    BIN binMAC = {0,0};

    QString strAlg = mHMACHashCombo->currentText();

    berApplet->log( QString( "Count = %1").arg( strCount ));
    berApplet->log( QString( "Klen = %1").arg( strKLen ));
    berApplet->log( QString( "Tlen = %1").arg(strTLen));
    berApplet->log( QString( "Key = %1").arg( strKey ));
    berApplet->log( QString( "Msg = %1").arg( strMsg ));


    JS_BIN_decodeHex( strKey.toStdString().c_str(), &binKey );
    JS_BIN_decodeHex( strMsg.toStdString().c_str(), &binMsg );

    ret = JS_PKI_genHMAC( strAlg.toStdString().c_str(), &binMsg, &binKey, &binMAC );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to gen HMAC ret:%1").arg(ret));
        goto end;
    }

    berApplet->log( QString( "Mac = %1").arg(getHexString(binMAC.pVal, binMAC.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binMAC );

    return ret;
}

int CAVPDlg::makePBKDF( int nIteration, const QString strPass, QString strSalt, int nKLen )
{
    int ret = 0;

    BIN binSalt = {0,0};
    BIN binKey = {0,0};

    QString strAlg = mPBKDFAlgCombo->currentText();

    ret = JS_PKI_PBKDF2( strPass.toStdString().c_str(), &binSalt, nIteration, strAlg.toStdString().c_str(), nKLen, &binKey );
    if( ret != 0 ) goto end;

    berApplet->log( QString( "Password = %1").arg( strPass) );
    berApplet->log( QString( "Salt = %1").arg(getHexString( binSalt.pVal, binSalt.nLen)));
    berApplet->log( QString( "KLen = %1" ).arg( nKLen ));
    berApplet->log( QString( "MK = %1").arg( getHexString( binKey.pVal, binKey.nLen )));
    berApplet->log( "" );

end:
    JS_BIN_reset( &binSalt );
    JS_BIN_reset( &binKey );
    return ret;
}


int CAVPDlg::makeDRBG( int nReturnedBitsLen,
              const QString strAlg,
              int nDF,
              int nPR,
              const QString strEntropyInput,
              const QString strNonce,
              const QString strPersonalizationString,
              const QString strEntropyInputReseed,
              const QString strAdditionalInputReseed,
              const QString strAdditionalInput1,
              const QString strAdditionalInput2,
              bool bInfo )
{
    int ret = 0;

    BIN binEntropyInput = {0,0};
    BIN binNonce = {0,0};
    BIN binPersionalizationString = {0,0};
    BIN binEntropyInputReseed = {0,0};
    BIN binAdditionalInputReseed = {0,0};
    BIN binAdditionalInput1 = {0,0};
    BIN binAdditionalInput2 = {0,0};
    BIN binDRBG = {0,0};


    JS_BIN_decodeHex( strEntropyInput.toStdString().c_str(), &binEntropyInput );
    JS_BIN_decodeHex( strNonce.toStdString().c_str(), &binNonce );
    JS_BIN_decodeHex( strPersonalizationString.toStdString().c_str(), &binPersionalizationString );
    JS_BIN_decodeHex( strEntropyInputReseed.toStdString().c_str(), &binEntropyInputReseed );
    JS_BIN_decodeHex( strAdditionalInputReseed.toStdString().c_str(), &binAdditionalInputReseed );
    JS_BIN_decodeHex( strAdditionalInput1.toStdString().c_str(), &binAdditionalInput1 );
    JS_BIN_decodeHex( strAdditionalInput2.toStdString().c_str(), &binAdditionalInput2 );

    ret = JS_PKI_genCTR_DRBG(
                nReturnedBitsLen,
                nDF,
                nPR,
                strAlg.toStdString().c_str(),
                &binEntropyInput,
                &binNonce,
                &binPersionalizationString,
                &binEntropyInputReseed,
                &binAdditionalInputReseed,
                &binAdditionalInput1,
                &binAdditionalInput2,
                &binDRBG );

    if( ret != 0 ) goto end;

    berApplet->log( QString( "EntropyInput = %1" ).arg( strEntropyInput));
    berApplet->log( QString( "Nonce = %1" ).arg( strNonce));
    berApplet->log( QString( "PersonalizationString  = %1").arg( strPersonalizationString));
    berApplet->log( QString( "EntropyInputReseed = %1").arg( strEntropyInputReseed ));
    berApplet->log( QString( "AdditionalInputReseed = %1").arg( strAdditionalInputReseed));
    berApplet->log( QString( "AdditionalInput = %1").arg( strAdditionalInput1 ));
    berApplet->log( QString( "AdditionalInput = %1").arg( strAdditionalInput2 ));
    berApplet->log( QString( "ReturnedBits = %1").arg( getHexString( binDRBG.pVal, binDRBG.nLen )));
    berApplet->log( "" );

    if( bInfo ) mDRBG2ReturnedBitsText->setPlainText( getHexString( binDRBG.pVal, binDRBG.nLen ));

end :
    JS_BIN_reset( &binEntropyInput );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binPersionalizationString );
    JS_BIN_reset( &binEntropyInputReseed );
    JS_BIN_reset( &binAdditionalInputReseed );
    JS_BIN_reset( &binAdditionalInput1 );
    JS_BIN_reset( &binAdditionalInput2 );
    JS_BIN_reset( &binDRBG );

    return ret;
}

int CAVPDlg::makeRSA_ES_DET( const QString strPri, const QString strC )
{
    int ret = 0;
    BIN binC = {0,0};
    BIN binM = {0,0};
    BIN binPri = {0,0};

    JS_BIN_decodeHex( strPri.toStdString().c_str(), &binPri );
    JS_BIN_decodeHex( strC.toStdString().c_str(), &binC );

    /* need to set private key */

    ret = JS_PKI_RSADecryptWithPri( JS_PKI_RSA_PADDING_V21, &binC, &binPri, &binM );
    if( ret != 0 ) goto end;


    berApplet->log( QString( "C = %1").arg(getHexString( binC.pVal, binC.nLen )));
    berApplet->log( QString( "M = %1").arg(getHexString( binM.pVal, binM.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binC );
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binPri );

    return ret;
}

int CAVPDlg::makeRSA_ES_ENT( const QString strPub, const QString strM )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binC = {0,0};
    BIN binPub = {0,0};

    JS_BIN_decodeHex( strPub.toStdString().c_str(), &binPub );
    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );

    /* need to set public key */

    ret = JS_PKI_RSAEncryptWithPub( JS_PKI_RSA_PADDING_V21, &binM, &binPub, &binC );
    if( ret != 0 ) goto end;

    berApplet->log( QString( "M = %1").arg(getHexString( binM.pVal, binM.nLen )));
    berApplet->log( QString( "C = %1").arg(getHexString( binC.pVal, binC.nLen )));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binC );
    JS_BIN_reset( &binPub );

    return ret;
}

int CAVPDlg::makeRSA_ES_KGT( int nKeyLen, int nE, int nCount )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRSAKeyVal sKeyVal;

    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPub );
        JS_BIN_reset( &binPri );
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        ret = JS_PKI_RSAGenKeyPair( nKeyLen, nE, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        berApplet->log( QString( "n = %1").arg( sKeyVal.pN));
        berApplet->log( QString( "e = %1").arg( sKeyVal.pE ));
        berApplet->log( QString( "q = %1").arg( sKeyVal.pQ ));
        berApplet->log( QString( "p = %1").arg( sKeyVal.pP ));
        berApplet->log( QString( "d = %1").arg( sKeyVal.pD ));
        berApplet->log( "" );

        JS_PKI_resetRSAKeyVal( &sKeyVal );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeRSA_PSS_KPG( int nLen, int nCount )
{
    int ret = 0;

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    JRSAKeyVal sKeyVal;


    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPub );
        JS_BIN_reset( &binPri );
        memset( &sKeyVal, 0x00, sizeof(sKeyVal));

        ret = JS_PKI_RSAGenKeyPair( nLen, 65537, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getRSAKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        berApplet->log( QString( "v = %1").arg( sKeyVal.pE ));
        berApplet->log( QString( "p1 = %1").arg( sKeyVal.pP));
        berApplet->log( QString( "p2 = %1").arg( sKeyVal.pQ));
        berApplet->log( QString( "n = %1").arg( sKeyVal.pN ));
        berApplet->log( QString( "s = %1").arg( sKeyVal.pD));
        berApplet->log( "" );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeRSA_PSS_SGT( int nE, const QString strHash, const QString strM )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binS = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};


    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );

    ret = JS_PKI_RSAGenKeyPair( 2048, nE, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_RSAMakeSign( strHash.toStdString().c_str(), JS_PKI_RSA_PADDING_V21, &binM, &binPri, &binS );
    if( ret != 0 ) goto end;

    berApplet->log( QString( "M = %1").arg( getHexString(binM.pVal, binM.nLen)));
    berApplet->log( QString( "S = %1").arg(getHexString(binS.pVal, binS.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );

    return ret;
}

int CAVPDlg::makeRSA_PSS_SVT( const QString strE, const QString strN, const QString strHash, const QString strM, const QString strS )
{
    int ret = 0;
    BIN binM = {0,0};
    BIN binS = {0,0};
    BIN binPub = {0,0};

    JRSAKeyVal sKeyVal;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    JS_PKI_setRSAKeyVal( &sKeyVal, strN.toStdString().c_str(), strE.toStdString().c_str(), NULL, NULL, NULL, NULL, NULL, NULL );

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );
    JS_BIN_decodeHex( strS.toStdString().c_str(), &binS );

    ret = JS_PKI_encodeRSAPublicKey( &sKeyVal, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_RSAVerifySign( strHash.toStdString().c_str(), JS_PKI_RSA_PADDING_V21, &binM, &binS, &binPub );

    berApplet->log( QString( "M = %1").arg( getHexString(binM.pVal, binM.nLen)));
    berApplet->log( QString( "S = %1").arg(getHexString(binS.pVal, binS.nLen)));

    if( ret == 1 )
        berApplet->log( "Result = P" );
    else
        berApplet->log( "Result = F" );

    berApplet->log( "" );

    ret = 0;
end :
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binS );
    JS_BIN_reset( &binPub );
    JS_PKI_resetRSAKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDH_KPG( int nCount )
{
    int ret = 0;
    int nGroupID = JS_PKI_getNidFromSN( "prime256v1" );

    JECKeyVal sKeyVal;

    BIN binPub = {0,0};
    BIN binPri = {0,0};

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    for( int i = 0; i < nCount; i++ )
    {
        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );
        JS_PKI_resetECKeyVal( &sKeyVal );

        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        berApplet->log( QString( "d = %1").arg( sKeyVal.pPrivate));
        berApplet->log( QString( "Qx = %1").arg( getHexString( &binPub.pVal[1], binPub.nLen/2) ));
        berApplet->log( QString( "Qy = %1").arg( getHexString( &binPub.pVal[binPub.nLen/2+1], binPub.nLen/2)));
        berApplet->log( "" );

        if( ret != 0 ) goto end;
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDH_PKV( const QString strPubX, const QString strPubY )
{
    int ret = 0;

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    QString strParam = "prime256v1";

    JS_BIN_decodeHex( strPubX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strPubY.toStdString().c_str(), &binPubY );

    berApplet->log( QString( "Qx = %1" ).arg( strPubX ));
    berApplet->log( QString( "Qy = %1").arg( strPubY));

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binPubX, &binPubY );

    if( ret == 0 )
        berApplet->log( "Result = P" );
    else
        berApplet->log( "Result = F" );

    berApplet->log( "" );
    ret = 0;

end :
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

    return ret;
}

int CAVPDlg::makeECDH_KAKAT( const QString strRA, const QString strRB, const QString strKTA1X, const QString strKTA1Y )
{
    int ret = 0;


    BIN binRA = {0,0};
    BIN binRB = {0,0};
    BIN binKTA1X = {0,0};
    BIN binKTA1Y = {0,0};

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    BIN binSecret = {0,0};

    JS_BIN_decodeHex( strRA.toStdString().c_str(), &binRA );
    JS_BIN_decodeHex( strRB.toStdString().c_str(), &binRB );
    JS_BIN_decodeHex( strKTA1X.toStdString().c_str(), &binKTA1X );
    JS_BIN_decodeHex( strKTA1Y.toStdString().c_str(), &binKTA1Y );

    ret = JS_PKI_genECPubKey( "prime256v1", &binRA, &binPubX, &binPubY );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECDHSecretWithValue( "prime256v1", &binRB, &binPubX, &binPubY, &binSecret );
    if( ret != 0 ) goto end;

    berApplet->log( "j = 1" );
    berApplet->log( QString( "rA = %1").arg( strRA ));
    berApplet->log( QString( "rB = %1").arg( strRB ));
    berApplet->log( QString( "KTA1x = %1").arg( strKTA1X ));
    berApplet->log( QString( "KTA1y = %1").arg( strKTA1Y ));
    berApplet->log( QString( "KABx = %1").arg(getHexString( &binSecret.pVal[0], 32)));

    /* need to check secret length */
//    berApplet->log( QString( "KABy = %1").arg(getHexString( &binSecret.pVal[32], 32)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binRA );
    JS_BIN_reset( &binRB );
    JS_BIN_reset( &binKTA1X );
    JS_BIN_reset( &binKTA1Y );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    JS_BIN_reset( &binSecret );

    return ret;
}

int CAVPDlg::makeECDSA_KPG( int nNum )
{
    int ret = 0;
    int nGroupID = JS_PKI_getNidFromSN( "prime256v1" );

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    JECKeyVal sKeyVal;
    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    for( int i = 0; i < nNum; i++ )
    {
        JS_PKI_resetECKeyVal( &sKeyVal );
        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binPub );

        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
        if( ret != 0 ) goto end;

        berApplet->log( QString( "X = %1").arg( sKeyVal.pPrivate ));
        berApplet->log( QString( "Yx = %1").arg( sKeyVal.pPubX ));
        berApplet->log( QString( "Yy = %1").arg( sKeyVal.pPubY ));
        berApplet->log( "" );
    }

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDSA_PKV( const QString strYX, const QString strYY )
{
    int ret = 0;

    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    QString strParam = "prime256v1";

    JS_BIN_decodeHex( strYX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strYY.toStdString().c_str(), &binPubY );

    ret = JS_PKI_IsValidECCPubKey( strParam.toStdString().c_str(), &binPubX, &binPubY );

    berApplet->log( QString( "Yx = %1" ).arg( strYX ));
    berApplet->log( QString( "Yy = %1").arg( strYY ));

    if( ret == 1 )
        berApplet->log( "Result = P" );
    else
        berApplet->log( "Result = F" );

    berApplet->log( "" );

end:
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    return 0;
}

int CAVPDlg::makeECDSA_SGT( const QString strM )
{
    int ret = 0;
    int nGroupID = JS_PKI_getNidFromSN( "prime256v1" );

    BIN binPub = {0,0};
    BIN binPri = {0,0};
    BIN binM = {0,0};
    BIN binSign = {0,0};
    BIN binSignR = {0,0};
    BIN binSignS = {0,0};

    JECKeyVal   sKeyVal;

    memset( &sKeyVal, 0x00, sizeof(sKeyVal));

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );

    ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
    if( ret != 0 ) goto end;

    ret = JS_PKI_getECKeyVal( &binPri, &sKeyVal );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCMakeSign( "SHA256", &binM, &binPri, &binSign );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCSignValue( &binSign, &binSignR, &binSignS );
    if( ret != 0 ) goto end;

    berApplet->log( QString( "M = %1").arg( strM ));
    berApplet->log( QString( "Yx = %1").arg( sKeyVal.pPubX ));
    berApplet->log( QString( "Yy = %1").arg( sKeyVal.pPubY ));
    berApplet->log( QString( "R = %1").arg(getHexString(binSignR.pVal, binSignR.nLen)));
    berApplet->log( QString( "S = %1").arg(getHexString(binSignS.pVal, binSignS.nLen)));
    berApplet->log( "" );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binM );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binSignR );
    JS_BIN_reset( &binSignS );

    JS_PKI_resetECKeyVal( &sKeyVal );

    return ret;
}

int CAVPDlg::makeECDSA_SVT( const QString strM, const QString strYX, const QString strYY, const QString strR, const QString strS )
{
    int ret = 0;
    int nIndex = 0;

    BIN binPub = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};
    BIN binSign = {0,0};
    BIN binSignR = {0,0};
    BIN binSignS = {0,0};
    BIN binM = {0,0};

    QString strParam = "prime256v1";

    JS_BIN_decodeHex( strM.toStdString().c_str(), &binM );
    JS_BIN_decodeHex( strYX.toStdString().c_str(), &binPubX );
    JS_BIN_decodeHex( strYY.toStdString().c_str(), &binPubY );
    JS_BIN_decodeHex( strR.toStdString().c_str(), &binSignR );
    JS_BIN_decodeHex( strS.toStdString().c_str(), &binSignS );

    ret = JS_PKI_encodeECPublicKeyValue( strParam.toStdString().c_str(), &binPubX, &binPubY, &binPub );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCEncodeSignValue( &binSignR, &binSignS, &binSign );
    if( ret != 0 ) goto end;

    ret = JS_PKI_ECCVerifySign( "SHA256", &binM, &binSign, &binPub );

    berApplet->log( QString( "M = %1").arg( strM ));
    berApplet->log( QString( "Yx = %1").arg( strYX));
    berApplet->log( QString( "Yy = %1").arg( strYY ));
    berApplet->log( QString( "R = %1" ).arg( strR ));
    berApplet->log( QString( "S = %1").arg( strS ));

    if( ret == 1 )
        berApplet->log( "Result = P" );
    else
        berApplet->log( "Result = F" );


    berApplet->log( "" );
    ret = 0;

end :
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );
    JS_BIN_reset( &binSign );
    JS_BIN_reset( &binSignR );
    JS_BIN_reset( &binSignS );
    JS_BIN_reset( &binM );

    return ret;
}
