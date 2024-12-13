#include <QFileInfo>
#include <QDir>
#include <QTextStream>
#include <QDateTime>

#include "key_list_dlg.h"
#include "ui_key_list_dlg.h"
#include "key_add_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "key_add_dlg.h"
#include "passwd_dlg.h"

#include "js_error.h"

static const QStringList kTypeList = { "ALL", "AES", "ARIA", "SEED", "TDES", "HMAC" };


KeyListDlg::KeyListDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mKeyAddBtn, SIGNAL(clicked()), this, SLOT(clickKeyAdd()));
    connect( mKeyDelBtn, SIGNAL(clicked()), this, SLOT(clickKeyDel()));
    connect( mKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickKeyView()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mGenMACBtn, SIGNAL(clicked()), this, SLOT(clickGenMAC()));
    connect( mEncDecBtn, SIGNAL(clicked()), this, SLOT(clickEncDec()));
    connect( mKeyTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeKeyType()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mManGroup->layout()->setSpacing(5);
    mManGroup->layout()->setMargin(5);
#endif
    initialize();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mOKBtn->setDefault(true);
}

KeyListDlg::~KeyListDlg()
{

}

void KeyListDlg::setManage( bool bMan )
{
    if( bMan == true )
    {
        connect( mKeyTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickKeyView()));
        mOKBtn->setHidden(true);
        mManGroup->setHidden(false);
    }
    else
    {
        connect( mKeyTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        mOKBtn->setHidden(false);
        mManGroup->setHidden( true );
    }
}

void KeyListDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void KeyListDlg::initialize()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 8/10;
#else
    int nWidth = width() * 8/10;
#endif

    QString strPath = berApplet->settingsMgr()->keyListPath();

    mSavePathText->setText( strPath );
    mKeyTypeCombo->addItems( kTypeList );

    QStringList sTableLabels = { tr( "Name" ), tr( "Algorithm"), tr( "IV Len"), tr( "LastModified") };

    mKeyTable->clear();
    mKeyTable->horizontalHeader()->setStretchLastSection(true);
    mKeyTable->setColumnCount( sTableLabels.size() );
    mKeyTable->setHorizontalHeaderLabels( sTableLabels );
    mKeyTable->verticalHeader()->setVisible(false);
    mKeyTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyTable->setColumnWidth( 0, nWidth * 5/10 );
    mKeyTable->setColumnWidth( 1, nWidth * 2/10 );
    mKeyTable->setColumnWidth( 2, nWidth * 2/10 );

    setManage(false);
}

void KeyListDlg::showEvent(QShowEvent *event)
{
    loadKeyList();
}

void KeyListDlg::closeEvent(QCloseEvent *event )
{

}

int KeyListDlg::getPlainKeyIV( const QString strData, QString& strKey, QString& strIV )
{
    int ret = 0;

    PasswdDlg passDlg;
    QStringList listKeyIV = strData.split(":");

    if( listKeyIV.size() < 1 ) return JSR_ERR;

    strKey = listKeyIV.at(0);

    if( strKey.contains( "{ENC}" ) == true )
    {
        QString strPasswd;
        QString strValue = strKey.mid(5);

        BIN binEnc = {0,0};
        BIN binKey = {0,0};

        if( passDlg.exec() != QDialog::Accepted )
            return JSR_ERR2;

        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binEnc );

        strPasswd = passDlg.mPasswdText->text();
        ret = getUnwrapKey( strPasswd.toStdString().c_str(), &binEnc, &binKey );
        strKey = getHexString( &binKey );
        JS_BIN_reset( &binEnc );
        JS_BIN_reset( &binKey );

        if( ret != 0 )
        {
            ret = JSR_PASSWORD_WRONG;
            return ret;
        }
    }

    if( listKeyIV.size() > 1 )
        strIV = listKeyIV.at(1);

    ret = 0;

    return ret;
}

void KeyListDlg::loadKeyList()
{
    int row = 0;
    str_data_.clear();

    mKeyTable->setRowCount(0);
    QString strPath = berApplet->settingsMgr()->keyListPath();
    QString strSelType = mKeyTypeCombo->currentText();

    QDir dir( strPath );

    for( const QFileInfo &file: dir.entryInfoList(QDir::Files) )
    {
        if( file.isFile() == false ) continue;

        QString strFilePath = file.filePath();

        QFile keyFile( strFilePath );

        if( keyFile.open( QIODevice::ReadOnly | QIODevice::Text ) == false )
        {
            berApplet->elog( QString( "fail to read key: %1" ).arg( strFilePath ));
            continue;
        }

        QString strName = file.baseName();

        QString strAlg;
        QString strKey;
        QString strIV;
        QString strData;

        QTextStream in( &keyFile );
        QString strLine = in.readLine();
        QDateTime date = file.lastModified();

        while( strLine.isNull() == false )
        {
            if( strLine.length() < 2 || strLine.at(0) == '#' )
            {
                strLine = in.readLine();
                continue;
            }

            QStringList nameVal = strLine.split(":");
            if( nameVal.size() < 2 )
            {
                strLine = in.readLine();
                continue;
            }

            QString strFirst = nameVal.at(0).simplified();
            QString strSecond = nameVal.at(1).simplified();

            if( strFirst == "ALG" )
                strAlg = strSecond;
            else if( strFirst == "Key" )
                strKey = strSecond;
            else if( strFirst == "IV" )
                strIV = strSecond;

            strLine = in.readLine();
        }

        keyFile.close();

        if( strSelType != "ALL" )
        {
            if( strSelType != strAlg ) continue;
        }

        mKeyTable->insertRow(row);
        mKeyTable->setRowHeight( row, 10 );
        QTableWidgetItem *item = new QTableWidgetItem( strName );


        strData = QString( "%1:%2" ).arg( strKey ).arg( strIV );
        item->setData( Qt::UserRole, strData );

        if( strKey.contains( "{ENC}") == true )
        {
            item->setIcon(QIcon(":/images/enc_key.png" ));
        }
        else
        {
            item->setIcon(QIcon(":/images/key.png" ));
        }

        mKeyTable->setItem( row, 0, item );
        mKeyTable->setItem( row, 1, new QTableWidgetItem(QString("%1").arg( strAlg)));
        mKeyTable->setItem( row, 2, new QTableWidgetItem(QString("%1 Bytes").arg( strIV.length() / 2 )));
        mKeyTable->setItem( row, 3, new QTableWidgetItem(QString("%1").arg( date.toString("yy-MM-dd hh:mm") )));
    }
}

void KeyListDlg::clickKeyAdd()
{
    QString strPath = berApplet->settingsMgr()->keyListPath();

    KeyAddDlg keyAdd;
    if( keyAdd.exec() == QDialog::Accepted )
    {
        QDir dir;
        BIN binIV = {0,0};
        BIN binData = {0,0};

        QString strName = keyAdd.mNameText->text();
        QString strAlg = keyAdd.mTypeCombo->currentText();
        QString strKey = keyAdd.getResKey();
        QString strIV = keyAdd.mIVText->text();


        QString fullPath = QString( "%1/%2" ).arg( strPath ).arg( strName );
        QFile file( fullPath );

        if( file.exists( fullPath ) )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed" ).arg( strName ), this );
            return;
        }

        QString strInfo;

        getBINFromString( &binIV, keyAdd.mIVTypeCombo->currentText(), strIV );

        strInfo += QString( "ALG: %1\n" ).arg( strAlg );
        strInfo += QString( "Key: %1\n" ).arg( strKey);
        strInfo += QString( "IV: %1\n" ).arg( getHexString( &binIV ));

        JS_BIN_set( &binData, (unsigned char *)strInfo.toStdString().c_str(), strInfo.length() );
        JS_BIN_fileWrite( &binData, fullPath.toLocal8Bit().toStdString().c_str() );

        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binData );

        loadKeyList();
    }
}

void KeyListDlg::clickKeyDel()
{
    QDir dir;

    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );
    QString strPath = berApplet->settingsMgr()->keyListPath();

    QString strSavePath;

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    bool bVal = berApplet->yesOrCancelBox( tr( "Are you sure to delete the key" ), this, false );
    if( bVal == false ) return;

    strSavePath = QString( "%1/%2" ).arg( strPath ).arg( item->text() );
    dir.remove( strSavePath );

    loadKeyList();
}

void KeyListDlg::clickKeyView()
{
    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );
    QString strPath = berApplet->settingsMgr()->keyListPath();

    QString strSavePath;

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    KeyAddDlg keyDlg;

    keyDlg.setTitle( tr( "Symmetric Key View" ));
    int ret = keyDlg.readFile( item->text() );
    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to get symmetric key: %1").arg( ret ) );
        if( ret == JSR_PASSWORD_WRONG )
        {
            berApplet->warningBox( tr( "The password is incorrect" ), this );
        }
        return;
    }

    keyDlg.setReadOnly();
    keyDlg.exec();

    return;
}

void KeyListDlg::clickOK()
{
    str_data_.clear();

    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );
    QString strData;
    QStringList listKeyIV;
    QString strKey;
    QString strIV;

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    strData = item->data(Qt::UserRole).toString();
    int ret = getPlainKeyIV( strData, strKey, strIV );

    if( ret != 0 )
    {
        berApplet->elog( QString( "fail to get symmetric key: %1").arg( ret ) );
        if( ret == JSR_PASSWORD_WRONG )
        {
            berApplet->warningBox( tr( "The password is incorrect" ), this );
        }
        return;
    }

    str_data_ = QString( "%1:%2" ).arg( strKey ).arg( strIV );

    accept();
}

void KeyListDlg::changeKeyType()
{
    loadKeyList();
}

void KeyListDlg::clickGenMAC()
{
    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    QString strKey;
    QString strIV;
    QString strData = item->data(Qt::UserRole).toString();
    QStringList keyIV = strData.split(":");

    int ret = getPlainKeyIV( strData, strKey, strIV );
    if( ret != 0 ) return;

    berApplet->mainWindow()->mac2( strKey, strIV );
}

void KeyListDlg::clickEncDec()
{
    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    QString strKey;
    QString strIV;
    QString strData = item->data(Qt::UserRole).toString();

    int ret = getPlainKeyIV( strData, strKey, strIV );
    if( ret != 0 ) return;

    berApplet->mainWindow()->encDec2( strKey, strIV );
}
