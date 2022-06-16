#include <QStringList>
#include <QDir>
#include <QTextStream>
#include <QThread>
#include <QButtonGroup>

#include "js_bin.h"
#include "js_pki.h"

#include "cavp_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"

const QStringList kSymAlgList = { "AES", "ARIA", "SEED" };
const QStringList kSymModeList = { "ECB", "CBC", "CTR", "CFB", "OFB" };
const QStringList kAEAlgList = { "AES", "ARIA" };
const QStringList kAEModeList = { "GCM", "CCM" };
const QStringList kAETypeList = { "AE", "AD" };
const QStringList kSymTypeList = { "KAT", "MCT", "MMT", "AE", "AD" };
const QStringList kHashAlgList = { "MD5", "SHA1", "SHA-224", "SHA-256", "SHA-384", "SHA-512" };
const QStringList kHashTypeList = { "Short", "Long", "Monte" };

const QStringList kECDHType = { "KAKAT", "PKV", "KPG" };
const QStringList kECDSAType = { "KPG", "PKV", "SGT", "SVT" };
const QStringList kRSAESType = { "DET", "ENT", "KGT" };
const QStringList kRSA_PSSType = { "KPG", "SGT", "SVT" };


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
    connect( mDRBGRunBtn, SIGNAL(clicked()), this, SLOT(clickDRBGRun() ));

    connect( mPBKDFFindBtn, SIGNAL(clicked()), this, SLOT(clickPBKDFFind() ));
    connect( mPBKDFRunBtn, SIGNAL(clicked()), this, SLOT(clickPBKDFRun() ));

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

    QButtonGroup *pECCGroup = new QButtonGroup();
    pECCGroup->addButton( mECC_ECDSARadio );
    pECCGroup->addButton(mECC_ECDHRadio );
    mECC_ECDSARadio->setChecked(true);
    clickECC_ECDSARadio();

    QButtonGroup *pRSAGroup = new QButtonGroup();
    pRSAGroup->addButton( mRSA_ESRadio );
    pRSAGroup->addButton( mRSA_PSSRadio );
    mRSA_ESRadio->setChecked(true);
    clickRSA_ESRadio();
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

    return strPath;
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
                berApplet->log( QString( "Key = %1").arg( strKey ));
                berApplet->log( QString( "IV = %1").arg( strIV ));
                berApplet->log( QString( "PT = %1").arg( strPT ));

                ret = makeSymData( strKey, strIV, strPT );
            }

            strKey.clear();
            strIV.clear();
            strPT.clear();
        }

        strLine = strNext;
        nPos++;
    }
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
        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

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
        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

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

                if( ret != 0 ) return;
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
        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

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
                if( ret != 0 ) return;
            }
            else if( strSeed.length() > 0 )
            {
                ret = makeHashMCT( strSeed );
                return;
            }

            strMsg.clear();
            strLen.clear();
            strSeed.clear();
        }

        strLine = strNext;
        nPos++;
    }
}

void CAVPDlg::clickECCRun()
{
    berApplet->log( "ECCRun\n" );
}

void CAVPDlg::clickRSARun()
{
    berApplet->log( "RSARun\n" );
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
        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

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
        berApplet->log( QString( "%1 %2 %3").arg( nPos ).arg( nLen ).arg( strLine ));

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
                if( ret != 0 ) return;
            }

            strPasswd.clear();
            strSalt.clear();
        }

        strLine = strNext;
        nPos++;
    }
}

void CAVPDlg::clickSymFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mSymReqFileText->setText( strFile );
}

void CAVPDlg::clickAEFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mAEReqFileText->setText( strFile );
}

void CAVPDlg::clickHashFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mHashReqFileText->setText( strFile );
}

void CAVPDlg::clickHMACFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mHMACReqFileText->setText( strFile );
}

void CAVPDlg::clickECCFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mECCReqFileText->setText( strFile );
}

void CAVPDlg::clickRSAFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mRSAReqFileText->setText( strFile );
}

void CAVPDlg::clickDRBGFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
    if( strFile.length() > 0 )
        mDRBGReqFileText->setText( strFile );
}

void CAVPDlg::clickPBKDFFind()
{
    QString strPath = QDir::homePath();

    QString strFile = findFile( this, JS_FILE_TYPE_TXT, strPath );
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
    return 0;
}

int CAVPDlg::makeHashMCT( const QString strSeed )
{
    return 0;
}

int CAVPDlg::makeHMACData( const QString strCount, const QString strKLen, const QString strTLen, const QString strKey, const QString strMsg )
{
    return 0;
}

int CAVPDlg::makePBKDF( int nIteration, const QString strPass, QString strSalt, int nKLen )
{
    return 0;
}

int CAVPDlg::makeDRBG( int nReturnedBitsLen,
              const QString strEntropyInput,
              const QString strNonce,
              const QString strPersonalizationString,
              const QString strEntropyInputReseed,
              const QString strAdditionalInputReseed,
              const QString strAdditionalInput1,
              const QString strAdditionalInput2 )
{
    return 0;
}
