#include "time_stamp_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"
#include "settings_mgr.h"

#include <QSettings>

const QString kTSPUsedURL = "TSPUsedURL";
const QString kTSPConfig = "TSPConfig";

TimeStampDlg::TimeStampDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

TimeStampDlg::~TimeStampDlg()
{

}

void TimeStampDlg::initUI()
{
    mURLCombo->setEditable( true );
    mHashCombo->addItems( kHashList );
    mHashCombo->setCurrentText( berApplet->settingsMgr()->getDefaultHash() );

    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mPolicyText->setPlaceholderText( "1.2.3.4" );
}

void TimeStampDlg::initialize()
{
    QString tspConfig = getTSPConfig();
    QStringList configList = tspConfig.split( "##" );

    for( int i = 0; i < configList.size(); i++ )
    {
        QString strPart = configList.at(i);
        QStringList listVal = strPart.split( "$" );
        if( listVal.size() < 2 ) continue;

        QString strName = listVal.at(0);
        QString strValue = listVal.at(1);

        if( strName == "URL" )
            mURLCombo->setCurrentText( decodeBase64( strValue ) );
        else if( strName == "Hash" )
            mHashCombo->setCurrentText( decodeBase64( strValue ) );
        else if( strName == "policy" )
            mPolicyText->setText( decodeBase64( strValue ) );
        else if( strName == "UseNonce" )
            mUseNonceCheck->setChecked( strValue.toInt() );
        else if( strName == "Auth" )
            mAuthGroup->setChecked( strValue.toInt() );
        else if( strName == "User" )
            mUserNameText->setText( decodeBase64( strValue ) );
        else if( strName == "Pass" )
            mPasswdText->setText( decodeBase64( strValue ) );
    }
}

void TimeStampDlg::clickOK()
{
    QString strURL = mURLCombo->currentText();
    QString strPolicy = mPolicyText->text();
    QString strHash = mHashCombo->currentText();
    QString strSet;
    QString strUserBase64;
    QString strPassBase64;

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a TSP URL" ), this );
        mURLCombo->setFocus();
        return;
    }

    if( mAuthGroup->isChecked() == true )
    {
        QString strUserName = mUserNameText->text();
        QString strPasswd = mPasswdText->text();

        if( strUserName.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a username" ), this );
            mUserNameText->setFocus();
            return;
        }

        if( strPasswd.length() < 1 )
        {
            berApplet->warningBox( tr( "Enter a password" ), this );
            mPasswdText->setFocus();
            return;
        }
    }

    strUserBase64 = encodeBase64( mUserNameText->text() );
    strPassBase64 = encodeBase64( mPasswdText->text() );

    strSet = QString( "URL$%1##Hash$%2##policy$%3##UseNonce$%4##Auth$%5##User$%6##Pass$%7" )
                 .arg( encodeBase64(strURL) ).arg( encodeBase64( strHash ) )
                 .arg( encodeBase64( strPolicy ) ).arg( mUseNonceCheck->isChecked() )
                 .arg( mAuthGroup->isChecked() ).arg( strUserBase64 ).arg( strPassBase64 );

    setTSPConfig( strSet );

    accept();
}

QStringList TimeStampDlg::getUsedURL()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTSPUsedURL ).toStringList();
    settings.endGroup();

    return retList;
}

void TimeStampDlg::setUsedURL( const QString strURL )
{
    if( strURL.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    QStringList list = settings.value( kTSPUsedURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kTSPUsedURL, list );
    settings.endGroup();

    mURLCombo->clear();
    mURLCombo->addItems( list );
}

QString TimeStampDlg::getTSPConfig()
{
    QSettings settings;
    QString retList;

    settings.beginGroup( kSettingBer );
    retList = settings.value( kTSPConfig ).toString();
    settings.endGroup();

    return retList;
}

void TimeStampDlg::setTSPConfig( const QString strConfig )
{
    if( strConfig.length() <= 4 ) return;

    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTSPConfig, strConfig );
    settings.endGroup();
}
