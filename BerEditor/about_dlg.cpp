/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
        version_label_ = tr( "%1 [Version %2]").arg(berApplet->getBrand()).arg(STRINGIZE(BER_EDITOR_VERSION));
    else
        version_label_ = tr( "%1 [Unlicensed Version %2]").arg(berApplet->getBrand()).arg(STRINGIZE(BER_EDITOR_VERSION));

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
    mCopyRightText->setOpenExternalLinks(true);

    showInfo();
    showCopyright();

#ifdef _AUTO_UPDATE
    mCheckUpdatBtn->show();
#else
    mCheckUpdatBtn->hide();
#endif


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

    tabWidget->setCurrentIndex(0);
}

void AboutDlg::showInfo()
{
#if 0
    QString strAbout = tr("This program is a freeware tool created using open source."
                          "If you do not use this for commercial purposes, you can use it freely " );

    strAbout += "<br><br>Copyright (C) 2024 JayKim &lt;jykim74@gmail.com&gt;";
#else

    QString strAbout = "Copyright (C) 2024 JayKim &lt;jykim74@gmail.com&gt;";
    strAbout += "<br><br>";
    strAbout += "All rights reserved.";
    strAbout += "<br><br>";

    strAbout += " Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:";
    strAbout += "<br><br>";

    strAbout += " - Redistributions of source code must retain the above copyright notice,this list of conditions and the following disclaimer.";
    strAbout += "<br><br>";

    strAbout += " - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.";
    strAbout += "<br><br>";

    strAbout += " - Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.";
    strAbout += "<br><br>";

    strAbout +=
        "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "
        "\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT "
        "LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS "
        " FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE "
        " COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, "
        " INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES ";
        " (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR "
        " SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) "
        " HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, "
        " STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) "
        " ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF "
        " ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.";


    strAbout +=
        "This program links to software with different licenses from: "
        "<br><br>"
        " - https://www.openssl.org ( Apache-2.0 )<br>"
        "- https://www.qt.io ( LGPLv3 )<br>"
        "- https://www.openldap.org ( The OpenLDAP Public )<br>"
        "- https://www.gnu.org/software/libtool ( LGPLv3 )";

#endif
    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "<br><br>Library: ";
    strAbout += strLibVersion;
    strAbout += "<br>";
    strAbout += berApplet->getBrand();
    strAbout += " : ";
    strAbout += getBuild();

    mAboutText->setHtml( strAbout );
}

void AboutDlg::showCopyright()
{
    QString strCopyRight;

    strCopyRight = tr("Third party software that may be contained in this application.");

    strCopyRight += "<br><br><b>OpenSSL 3.0.8</b>";
    strCopyRight += "<br>- https://www.openssl.org";
    strCopyRight += "<br>- <a href=https://github.com/openssl/openssl/blob/master/LICENSE.txt>Apache 2.0 License</a>";

#ifdef Q_OS_MACOS
    strCopyRight += "<br><br><b>QT 5.15.2</b>";
#else
    strCopyRight += "<br><br><b>QT 5.13.2</b>";
#endif
    strCopyRight += "<br>- https://www.qt.io";
    strCopyRight += "<br>- <a href=https://www.qt.io/licensing/open-source-lgpl-obligations>LGPL 3.0 License</a>";

    strCopyRight += "<br><br><b>OpenLDAP</b>";
    strCopyRight += "<br>- https://www.openldap.org";
    strCopyRight += "<br>- <a href=https://www.openldap.org/doc/admin20/license.html>The OpenLDAP Public License</a>";

    strCopyRight += "<br><br><b>ltdl</b>";
    strCopyRight += "<br>- https://www.gnu.org/software/libtool";
    strCopyRight += "<br>- <a href=https://www.gnu.org/licenses/lgpl-3.0.en.html>LGPL 3.0 Licese</a>";

#ifdef Q_OS_WIN
    strCopyRight += "<br><br><b>WinSparkle</b>";
    strCopyRight += "<br>- https://winsparkle.org";
    strCopyRight += "<br>- <a href=https://github.com/vslavik/winsparkle/blob/master/COPYING>MIT license</a>";
#endif

#ifdef Q_OS_MACOS
    strCopyRight += "<br><br><b>Sparkle</b>";
    strCopyRight += "<br>- https://sparkle-project.org";
    strCopyRight += "<br>- <a href=https://github.com/sparkle-project/Sparkle/blob/2.x/LICENSE>MIT license</a>";
#endif

    strCopyRight += "<br><br><b>jsmn</b>";
    strCopyRight += "<br>- https://zserge.com/jsmn";
    strCopyRight += "<br>- <a href=https://github.com/zserge/jsmn/blob/master/LICENSE>MIT License</a>";

    strCopyRight += "<br><br><b>shamir-secret</b>";
    strCopyRight += "<br>- https://github.com/KPN-CISO/shamir-secret";
    strCopyRight += "<br>- <a href=https://github.com/KPN-CISO/shamir-secret/blob/master/LICENSE>MIT License</a>";

    strCopyRight += "<br><br><b>sscep</b>";
    strCopyRight += "<br>- https://github.com/certnanny/sscep";
    strCopyRight += "<br>- <a href=https://github.com/certnanny/sscep/blob/master/COPYING>OpenSSL License</a>";


    strCopyRight += "<br><br><b>OpenKMIP</b>";
    strCopyRight += "<br>- https://github.com/OpenKMIP/libkmip";
    strCopyRight += "<br>- <a href=https://github.com/OpenKMIP/libkmip/blob/master/LICENSE>Apache 2.0 License</a>";

    mCopyRightText->setText( strCopyRight );
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
