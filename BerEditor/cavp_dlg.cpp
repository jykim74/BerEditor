#include <QStringList>
#include <QDir>
#include <QTextStream>
#include <QThread>

#include "cavp_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"

const QStringList kSymAlgList = { "AES", "ARIA", "SEED" };
const QStringList kSymModeList = { "ECB", "CBC", "CTR", "CFB", "OFB", "GCM" };
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

    connect( mSymFindBtn, SIGNAL(clicked()), this, SLOT(clickSymFind() ));
    connect( mSymRunBtn, SIGNAL(clicked()), this, SLOT(clickSymRun() ));

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

    mHashAlgCombo->addItems( kHashAlgList );
    mHashTypeCombo->addItems( kHashTypeList );

    mHMACHashCombo->addItems( kHashAlgList );
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


void CAVPDlg::clickSymRun()
{

}

void CAVPDlg::clickHashRun()
{

}

void CAVPDlg::clickHMACRun()
{

}

void CAVPDlg::clickECCRun()
{

}

void CAVPDlg::clickRSARun()
{

}

void CAVPDlg::clickDRBGRun()
{

}

void CAVPDlg::clickPBKDFRun()
{

}

void CAVPDlg::clickSymFind()
{

}

void CAVPDlg::clickHashFind()
{

}

void CAVPDlg::clickHMACFind()
{

}

void CAVPDlg::clickECCFind()
{

}

void CAVPDlg::clickRSAFind()
{

}

void CAVPDlg::clickDRBGFind()
{

}

void CAVPDlg::clickPBKDFFind()
{

}
