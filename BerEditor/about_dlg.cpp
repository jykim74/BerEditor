#include "about_dlg.h"
#include "ber_applet.h"
#include "auto_update_service.h"
#include "js_gen.h"


AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(berApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );

    version_label_ = tr( "About %1 (%2)").arg(berApplet->getBrand()).arg(STRINGIZE(BER_VIEWER_VERSION));
    mVersionLabel->setText( version_label_ );

    connect(mOKBtn, SIGNAL(clicked()), this, SLOT(close()));
#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() )
    {
        mCheckUpdatBtn->setVisible(true);
        connect(mCheckUpdatBtn, SIGNAL(clicked()), this, SLOT(checkUpdate()));
    }
#endif

    QString strAbout = tr("This is freeware tool to decode ASN.1 and BER "
            "If you do not use this for commercial purposes, "
            "you can use it freely "
            "If you have any opinions on this tool, please send me a mail." );

    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "\r\n\r\nLibrary: ";
    strAbout += strLibVersion;

    strAbout += "\r\n";
    strAbout += getBuild();
    strAbout += "\r\n";

    strAbout += "Copyright (C) 2020 ~ 2021 JongYeob Kim";
    strAbout += "\r\n\r\n";
    strAbout += "http://jykim74.tistory.com";
    strAbout += "\r\n";
    strAbout += "mailto: jykim74@gmail.com";

    mAboutText->setText( strAbout );
}

AboutDlg::~AboutDlg()
{
//    delete ui;
}

QString AboutDlg::getBuild()
{
    QString strBuild = QString( "Build Date: %1 %2").arg( __DATE__ ).arg( __TIME__ );
    return strBuild;
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
