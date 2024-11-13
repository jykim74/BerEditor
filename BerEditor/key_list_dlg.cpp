#include <QFileInfo>
#include <QDir>
#include <QTextStream>

#include "key_list_dlg.h"
#include "ui_key_list_dlg.h"
#include "key_add_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"
#include "key_add_dlg.h"

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
#endif
    initialize();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyListDlg::~KeyListDlg()
{

}

void KeyListDlg::setManage( bool bSel )
{
    if( bSel == true )
    {
        mOKBtn->setHidden(true);
        mManGroup->setHidden(false);
    }
    else
    {
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

    QStringList sTableLabels = { tr( "Name" ), tr( "Algorithm"), tr("Length"), tr( "IV Len") };

    mKeyTable->clear();
    mKeyTable->horizontalHeader()->setStretchLastSection(true);
    mKeyTable->setColumnCount( sTableLabels.size() );
    mKeyTable->setHorizontalHeaderLabels( sTableLabels );
    mKeyTable->verticalHeader()->setVisible(false);
    mKeyTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyTable->setColumnWidth( 0, nWidth * 6/10 );
    mKeyTable->setColumnWidth( 1, nWidth * 2/10 );
    mKeyTable->setColumnWidth( 3, nWidth * 1/10 );
}

void KeyListDlg::showEvent(QShowEvent *event)
{
    loadKeyList();
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
        QString strLength;
        QString strAlg;
        QString strKey;
        QString strIV;
        QString strData;

        QTextStream in( &keyFile );
        QString strLine = in.readLine();

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
            else if( strFirst == "Length" )
                strLength = strSecond;
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
        item->setIcon(QIcon(":/images/key.png" ));

        strData = QString( "%1:%2" ).arg( strKey ).arg( strIV );
        item->setData( Qt::UserRole, strData );

        mKeyTable->setItem( row, 0, item );
        mKeyTable->setItem( row, 1, new QTableWidgetItem(QString("%1").arg( strAlg)));
        mKeyTable->setItem( row, 2, new QTableWidgetItem( QString("%1" ).arg( strLength )));
        mKeyTable->setItem( row, 3, new QTableWidgetItem(QString("%1").arg( strIV.length() / 2 )));
    }
}

void KeyListDlg::clickKeyAdd()
{
    QString strPath = berApplet->settingsMgr()->keyListPath();

    KeyAddDlg keyAdd;
    if( keyAdd.exec() == QDialog::Accepted )
    {
        QDir dir;
        BIN binKey = {0,0};
        BIN binIV = {0,0};
        BIN binData = {0,0};

        QString strName = keyAdd.mNameText->text();
        QString strAlg = keyAdd.mTypeCombo->currentText();
        QString strKey = keyAdd.mKeyText->text();
        QString strIV = keyAdd.mIVText->text();
        int nLen = keyAdd.mKeyLenCombo->currentText().toInt();

        QString fullPath = QString( "%1/%2" ).arg( strPath ).arg( strName );
        QFile file( fullPath );

        if( file.exists( fullPath ) )
        {
            berApplet->warningBox( tr( "The file(%1) is already existed" ).arg( strName ), this );
            return;
        }

        QString strInfo;

        getBINFromString( &binKey, keyAdd.mKeyTypeCombo->currentText(), strKey );
        getBINFromString( &binIV, keyAdd.mIVTypeCombo->currentText(), strIV );

        strInfo += QString( "ALG: %1\n" ).arg( strAlg );
        strInfo += QString( "Length: %1\n" ).arg( nLen );
        strInfo += QString( "Key: %1\n" ).arg( getHexString( &binKey ));
        strInfo += QString( "IV: %1\n" ).arg( getHexString( &binIV ));

        JS_BIN_set( &binData, (unsigned char *)strInfo.toStdString().c_str(), strInfo.length() );
        JS_BIN_fileWrite( &binData, fullPath.toLocal8Bit().toStdString().c_str() );

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binIV );
        JS_BIN_reset( &binData );
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
    keyDlg.readFile( item->text() );
    keyDlg.setReadOnly();
    keyDlg.exec();
}

void KeyListDlg::clickOK()
{
    str_data_.clear();

    QModelIndex idx = mKeyTable->currentIndex();
    QTableWidgetItem* item = mKeyTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no key to select" ), this );
        return;
    }

    str_data_ = item->data(Qt::UserRole).toString();

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

    if( keyIV.size() > 0 )
        strKey = keyIV.at(0);

    if( keyIV.size() > 1 )
        strIV = keyIV.at(1);

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
    QStringList keyIV = strData.split(":");

    if( keyIV.size() > 0 )
        strKey = keyIV.at(0);

    if( keyIV.size() > 1 )
        strIV = keyIV.at(1);

    berApplet->mainWindow()->encDec2( strKey, strIV );
}
