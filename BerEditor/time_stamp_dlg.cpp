#include "time_stamp_dlg.h"
#include "ber_applet.h"
#include "mainwindow.h"
#include "common.h"

#include <QSettings>

const QString kTSPUsedURL = "TSPUsedURL";

TimeStampDlg::TimeStampDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked(bool)), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mAuthCheck, SIGNAL(clicked()), this, SLOT(checkAuth()));

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
    QStringList usedList = getUsedURL();
    mURLCombo->addItems( usedList );

    mPolicyText->setPlaceholderText( "1.2.3.4" );
    checkAuth();
}

void TimeStampDlg::initialize()
{

}

void TimeStampDlg::clickOK()
{
    QString strURL = mURLCombo->currentText();
    QString strPolicy = mPolicyText->text();

    if( strURL.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a TSP URL" ), this );
        mURLCombo->setFocus();
        return;
    }

    if( mAuthCheck->isChecked() == true )
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

void TimeStampDlg::checkAuth()
{
    bool bVal = mAuthCheck->isChecked();

    mUserNameLabel->setEnabled( bVal );
    mUserNameText->setEnabled( bVal );
    mPasswdLabel->setEnabled( bVal );
    mPasswdText->setEnabled( bVal );
}
