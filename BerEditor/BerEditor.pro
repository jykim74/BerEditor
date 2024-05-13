#-------------------------------------------------
#
# Project created by QtCreator 2019-08-07T14:16:42
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

requires(qtConfig(filedialog))
qtHaveModule(printsupport): QT += printsupport

TARGET = BerEditor
TEMPLATE = app
PROJECT_VERSION = "1.8.2"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += BER_EDITOR_VERSION=$$PROJECT_VERSION
#DEFINES += _AUTO_UPDATE
DEFINES += USE_OCSP
#DEFINES += _USE_RC_LCN

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11


SOURCES += \
    about_dlg.cpp \
    auto_update_service.cpp \
    ber_applet.cpp \
    ber_item.cpp \
    ber_item_delegate.cpp \
    ber_model.cpp \
    ber_tray_icon.cpp \
    ber_tree_view.cpp \
    cavp_dlg.cpp \
    cert_info_dlg.cpp \
    cert_pvd_dlg.cpp \
    cms_dlg.cpp \
    common.cpp \
    crl_info_dlg.cpp \
    data_encoder_dlg.cpp \
    dumpasn1.c \
    edit_value_dlg.cpp \
    enc_dec_dlg.cpp \
    gen_hash_dlg.cpp \
    gen_mac_dlg.cpp \
    gen_otp_dlg.cpp \
    get_uri_dlg.cpp \
    i18n_helper.cpp \
    insert_ber_dlg.cpp \
    insert_data_dlg.cpp \
    key_agree_dlg.cpp \
    key_man_dlg.cpp \
    lcn_info_dlg.cpp \
    main.cpp \
    mainwindow.cpp \
    num_trans_dlg.cpp \
    oid_info_dlg.cpp \
    pub_enc_dec_dlg.cpp \
    settings_dlg.cpp \
    settings_mgr.cpp \
    sign_verify_dlg.cpp \
    sss_dlg.cpp \
    ssl_verify_dlg.cpp \
    csr_info_dlg.cpp \
    trust_list_dlg.cpp \
    vid_dlg.cpp \
    make_value_dlg.cpp

HEADERS += \
    about_dlg.h \
    auto_update_service.h \
    ber_applet.h \
    ber_item.h \
    ber_item_delegate.h \
    ber_model.h \
    ber_tray_icon.h \
    ber_tree_view.h \
    cavp_dlg.h \
    cert_info_dlg.h \
    cert_pvd_dlg.h \
    cms_dlg.h \
    common.h \
    crl_info_dlg.h \
    data_encoder_dlg.h \
    edit_value_dlg.h \
    enc_dec_dlg.h \
    gen_hash_dlg.h \
    gen_mac_dlg.h \
    gen_otp_dlg.h \
    get_uri_dlg.h \
    i18n_helper.h \
    insert_ber_dlg.h \
    insert_data_dlg.h \
    key_agree_dlg.h \
    key_man_dlg.h \
    lcn_info_dlg.h \
    mainwindow.h \
    num_trans_dlg.h \
    oid_info_dlg.h \
    pub_enc_dec_dlg.h \
    settings_dlg.h \
    settings_mgr.h \
    sign_verify_dlg.h \
    singleton.h \
    sss_dlg.h \
    ssl_verify_dlg.h \
    csr_info_dlg.h \
    trust_list_dlg.h \
    vid_dlg.h \
    make_value_dlg.h



# Sparkle.framework 를 Qt/5.11.3/clang_64/lib/ 에 복사 해 주었음

mac {
    DEFINES += _AUTO_UPDATE

    QMAKE_INFO_PLIST = info.plist

    ICON = bereditor.icns
    QMAKE_LFLAGS += -Wl,-rpath,@loader_path/../Frameworks
    HEADERS += mac_sparkle_support.h
    OBJECTIVE_SOURCES += mac_sparkle_support.mm
    LIBS += -framework AppKit
    LIBS += -framework Carbon
    LIBS += -framework Foundation
    LIBS += -framework ApplicationServices
    LIBS += -framework Sparkle
    INCLUDEPATH += "/usr/local/Sparkle.framework/Headers"

    INCLUDEPATH += "/usr/local/include"
    CONFIG( debug, debug | release ) {
        message( "BerEditor Debug" );
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug" -lPKILib
        LIBS += -L"../../lib/mac/debug/openssl3/lib" -lcrypto -lssl
        INCLUDEPATH += "../../lib/mac/debug/openssl3/include"
    } else {
        message( "BerEditor Release" );
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release" -lPKILib
        LIBS += -L"../../lib/mac/openssl3/lib" -lcrypto -lssl
        INCLUDEPATH += "../../lib/mac/openssl3/include"
    }

    LIBS += -lldap -llber
    LIBS += -L"/usr/local/lib" -lltdl
}

linux {
    CONFIG( debug, debug | release ) {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug" -lPKILib
        LIBS += -L"../../lib/linux/debug/openssl3/lib64" -lcrypto -lssl
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Release" -lPKILib
        LIBS += -L"../../lib/linux/openssl3/lib64" -lcrypto -lssl
    }

    LIBS += -lltdl -lldap -llber
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = bereditor.ico
    INCLUDEPATH += "../../lib/win32/winsparkle/include"
    INCLUDEPATH += "C:\msys64\mingw32\include"

    contains(QT_ARCH, i386) {
        message( "32bit" )
        INCLUDEPATH += "../../PKILib/lib/win32/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw32\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
            LIBS += -L"../../lib/win32/debug/openssl3/lib" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
            LIBS += -L"../../lib/win32/openssl3/lib" -lcrypto -lssl
        }

        LIBS += -L"../../lib/win32" -lltdl -lldap -llber
        LIBS += -L"../../lib/win32/winsparkle/lib" -lWinSparkle -lws2_32
    } else {
        message( "64bit" );
        INCLUDEPATH += "../../PKILib/lib/win64/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw64\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug" -lPKILib
            LIBS += -L"../../lib/win64/debug/openssl3/lib64" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release" -lPKILib
            LIBS += -L"../../lib/win64/openssl3/lib64" -lcrypto -lssl
        }

        LIBS += -L"../../lib/win64" -lltdl -lldap -llber
        LIBS += -L"../../lib/win64/winsparkle/lib" -lWinSparkle -lws2_32
    }
}

FORMS += \
        about_dlg.ui \
        cavp_dlg.ui \
        cert_info_dlg.ui \
        cert_pvd_dlg.ui \
        cms_dlg.ui \
        crl_info_dlg.ui \
        data_encoder_dlg.ui \
        edit_value_dlg.ui \
        enc_dec_dlg.ui \
        gen_hash_dlg.ui \
        gen_mac_dlg.ui \
        gen_otp_dlg.ui \
        get_uri_dlg.ui \
        insert_ber_dlg.ui \
        insert_data_dlg.ui \
        key_agree_dlg.ui \
        key_man_dlg.ui \
        lcn_info_dlg.ui \
        mainwindow.ui \
        num_trans_dlg.ui \
        oid_info_dlg.ui \
        pub_enc_dec_dlg.ui \
        settings_dlg.ui \
        sign_verify_dlg.ui \
        sss_dlg.ui \
        ssl_verify_dlg.ui \
        csr_info_dlg.ui \
        trust_list_dlg.ui \
        vid_dlg.ui \
        make_value_dlg.ui

RESOURCES += \
    bereditor.qrc

TRANSLATIONS += i18n/bereditor_ko_KR.ts



target.path = i18n

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target



INCLUDEPATH += "../../PKILib"



DISTFILES += \
    oid.cfg
