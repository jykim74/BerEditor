#include <QDir>

#include "key_pair_man_dlg.h"
#include "gen_key_pair_dlg.h"
#include "make_csr_dlg.h"
#include "ber_applet.h"
#include "common.h"

#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "js_pki_key.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"

KeyPairManDlg::KeyPairManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mGenKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickGenKeyPair()));
    connect( mMakeCSRBtn, SIGNAL(clicked()), this, SLOT(clickMakeCSR()));

    connect( mFindSavePathBtn, SIGNAL(clicked()), this, SLOT(findSavePath()));
    connect( mFindPriKeyBtn, SIGNAL(clicked()), this, SLOT(findPriKey()));
    connect( mFindPubKeyBtn, SIGNAL(clicked()), this, SLOT(findPubKey()));
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mFindEncPriKeyBtn, SIGNAL(clicked()), this, SLOT(findEncPriKey()));
    connect( mFindPFXBtn, SIGNAL(clicked()), this, SLOT(findPFX()));

    connect( mPriClearBtn, SIGNAL(clicked()), this, SLOT(clearPriKey()));
    connect( mPubClearBtn, SIGNAL(clicked()), this, SLOT(clearPubKey()));
    connect( mCertClearBtn, SIGNAL(clicked()), this, SLOT(clearCert()));
    connect( mEncPriClearBtn, SIGNAL(clicked()), this, SLOT(clearEncPriKey()));
    connect( mPFXClearBtn, SIGNAL(clicked()), this, SLOT(clearPFX()));
    connect( mCSRClearBtn, SIGNAL(clicked()), this, SLOT(clearCSR()));

    connect( mPriTypeBtn, SIGNAL(clicked()), this, SLOT(typePriKey()));
    connect( mPubTypeBtn, SIGNAL(clicked()), this, SLOT(typePubKey()));
    connect( mCertTypeBtn, SIGNAL(clicked()), this, SLOT(typeCert()));

    connect( mCheckKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickCheckKeyPair()));
    connect( mEncryptBtn, SIGNAL(clicked()), this, SLOT(clickEncrypt()));
    connect( mEncodePFXBtn, SIGNAL(clicked()), this, SLOT(clickEncodePFX()));
    connect( mViewCertBtn, SIGNAL(clicked()), this, SLOT(clickViewCert()));
    connect( mDecryptBtn, SIGNAL(clicked()), this, SLOT(clickDecrypt()));
    connect( mDecodePFXBtn, SIGNAL(clicked()), this, SLOT(clickDecodePFX()));
    connect( mClearAllBtn, SIGNAL(clicked()), this, SLOT(clickClearAll()));
}

KeyPairManDlg::~KeyPairManDlg()
{

}

void KeyPairManDlg::clickGenKeyPair()
{
    GenKeyPairDlg genKeyPair;
    genKeyPair.exec();
}

void KeyPairManDlg::clickMakeCSR()
{
    MakeCSRDlg makeCSR;
    makeCSR.exec();
}

void KeyPairManDlg::clickCheckKeyPair()
{

}

void KeyPairManDlg::clickEncrypt()
{

}

void KeyPairManDlg::clickEncodePFX()
{

}

void KeyPairManDlg::clickViewCert()
{

}

void KeyPairManDlg::clickViewCSR()
{

}

void KeyPairManDlg::clickDecrypt()
{

}

void KeyPairManDlg::clickDecodePFX()
{

}

void KeyPairManDlg::clickClearAll()
{
    clearPriKey();
    clearPubKey();
    clearCert();
    clearEncPriKey();
    clearPFX();
    clearCSR();
}

void KeyPairManDlg::findSavePath()
{
    QString strPath = mSavePathText->text();

    if( strPath.length() < 1 )
    {
        strPath = QDir::homePath();
    }

    QString folderPath = findFolder( this, strPath );
    if( folderPath.length() > 0 )
        mSavePathText->setText( folderPath );
}

void KeyPairManDlg::findPriKey()
{
    QString strPath = mPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mPriPathText->setText( filePath );
}

void KeyPairManDlg::findPubKey()
{
    QString strPath = mPubPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPubPathText->setText( filePath );
}

void KeyPairManDlg::findCert()
{
    QString strPath = mCertPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( filePath.length() > 0 ) mCertPathText->setText( filePath );
}

void KeyPairManDlg::findEncPriKey()
{
    QString strPath = mEncPriPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( filePath.length() > 0 ) mEncPriPathText->setText( filePath );
}

void KeyPairManDlg::findPFX()
{
    QString strPath = mPFXPathText->text();

    if( strPath.length() < 1 )
    {
        strPath = mSavePathText->text();
    }

    QString filePath = findFile( this, JS_FILE_TYPE_BER, strPath );
    if( filePath.length() > 0 ) mPFXPathText->setText( filePath );
}

void KeyPairManDlg::clearPriKey()
{
    mPriPathText->clear();
}

void KeyPairManDlg::clearPubKey()
{
    mPubPathText->clear();
}

void KeyPairManDlg::clearCert()
{
    mCertPathText->clear();
}

void KeyPairManDlg::clearEncPriKey()
{
    mEncPriPathText->clear();
}

void KeyPairManDlg::clearPFX()
{
    mPFXPathText->clear();
}

void KeyPairManDlg::clearCSR()
{
    mCSRPathText->clear();
}

void KeyPairManDlg::decodePriKey()
{

}

void KeyPairManDlg::decodePubKey()
{

}

void KeyPairManDlg::decodeCert()
{

}

void KeyPairManDlg::decodeEncPriKey()
{

}

void KeyPairManDlg::decodePFX()
{

}

void KeyPairManDlg::decodeCSR()
{

}

void KeyPairManDlg::typePriKey()
{

}

void KeyPairManDlg::typePubKey()
{

}

void KeyPairManDlg::typeCert()
{

}
