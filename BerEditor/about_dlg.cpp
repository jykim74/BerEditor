#include "about_dlg.h"
#include "ber_applet.h"
#include "auto_update_service.h"
#include "js_gen.h"
#include "js_license.h"
#include "settings_mgr.h"

AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(berApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );

    initialize();

    if( berApplet->isLicense() )
        version_label_ = tr( "%1 [Ver %2]").arg(berApplet->getBrand()).arg(STRINGIZE(BER_EDITOR_VERSION));
    else
        version_label_ = tr( "%1 (Unlicensed Version) [Ver %2]").arg(berApplet->getBrand()).arg(STRINGIZE(BER_EDITOR_VERSION));

    mVersionLabel->setText( version_label_ );

    connect(mOKBtn, SIGNAL(clicked()), this, SLOT(close()));
#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() )
    {
        mCheckUpdatBtn->setVisible(true);
        connect(mCheckUpdatBtn, SIGNAL(clicked()), this, SLOT(checkUpdate()));
    }
#endif

    mAboutText->setOpenExternalLinks(true);

    QString strAbout = tr("This is freeware tool to decode and to encode ASN.1 and BER. "
                          "and to test cryptographic funtions"
            "If you do not use this for commercial purposes, "
            "you can use it freely "
            "If you have any opinions on this tool, please send me a mail." );

    strAbout += "<br><br>OpenSSL Version 3.0.8";
    strAbout += "<br>https://www.openssl.org";
    strAbout += "<br>Apache 2.0 License";

#ifdef Q_OS_MACOS
    strAbout += "<br><br>QT Version 5.15.2";
#else
    strAbout += "<br><br>QT Version 5.13.2";
#endif
    strAbout += "<br>https://www.qt.io";
    strAbout += "<br>LGPL 3.0 License";

    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "<br><br>Library: ";
    strAbout += strLibVersion;

    strAbout += "<br>";
    strAbout += getBuild();
    strAbout += "<br>";

    strAbout += "Copyright (C) 2020 ~ 2023 JongYeob Kim";
    strAbout += "<br><br>blog: ";
    strAbout += "<a href=https://jykim74.tistory.com>https://jykim74.tistory.com</a>";
    strAbout += "<br>mail: ";
    strAbout += "<a href=mailto:jykim74@gmail.com>jykim74@gmail.com</a>";

#ifdef _AUTO_UPDATE
    mCheckUpdatBtn->show();
#else
    mCheckUpdatBtn->hide();
#endif

//    mAboutText->setText( strAbout );
    mAboutText->setHtml( strAbout );
    mOKBtn->setDefault(true);
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

void AboutDlg::initialize()
{
    static QFont font;
    QString strFont = berApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    font.setBold(true);
    font.setPointSize(15);
    mVersionLabel->setFont(font);
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
