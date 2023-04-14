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

    version_label_ = tr( "About %1 [Ver %2]").arg(berApplet->getBrand()).arg(STRINGIZE(BER_VIEWER_VERSION));
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
    mOKBtn->setFocus();
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
