#include <QFileInfo>
#include <QDir>

#include "key_list_dlg.h"
#include "ui_key_list_dlg.h"
#include "key_add_dlg.h"
#include "common.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "settings_mgr.h"

static const QStringList kTypeList = { "ALL", "AES", "ARIA", "SEED", "TDES", "HMAC" };


KeyListDlg::KeyListDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mKeyAddBtn, SIGNAL(clicked()), this, SLOT(clickKeyAdd()));
    connect( mKeyDelBtn, SIGNAL(clicked()), this, SLOT(clickKeyDel()));
    connect( mKeyViewBtn, SIGNAL(clicked()), this, SLOT(clickKeyView()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    initialize();

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

KeyListDlg::~KeyListDlg()
{

}

void KeyListDlg::initialize()
{
    QString strPath = berApplet->settingsMgr()->keyListPath();

    mSavePathText->setText( strPath );
    mKeyTypeCombo->addItems( kTypeList );
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

}

void KeyListDlg::clickKeyView()
{

}
