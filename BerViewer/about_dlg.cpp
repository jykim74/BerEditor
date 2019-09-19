#include "about_dlg.h"
#include "ber_applet.h"
#include "auto_update_service.h"


AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    version_label_ = tr( "<H2>%1 (%2)<H2>").arg( "BerViewer").arg(STRINGIZE(BER_VIEWER_VERSION));
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
            "If you have any opinions on this tool, please send me a mail"
            "mailto : jykim74@gmail.com");

    mAboutText->setText( strAbout );
}

AboutDlg::~AboutDlg()
{
//    delete ui;
}


#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
