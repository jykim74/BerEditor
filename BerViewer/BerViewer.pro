#-------------------------------------------------
#
# Project created by QtCreator 2019-08-07T14:16:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

requires(qtConfig(filedialog))
qtHaveModule(printsupport): QT += printsupport

TARGET = BerViewer
TEMPLATE = app
PROJECT_VERSION = "0.9.7"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += BER_VIEWER_VERSION=$$PROJECT_VERSION

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
    data_encoder_dlg.cpp \
    dumpasn1.c \
    edit_value_dlg.cpp \
    enc_dec_dlg.cpp \
    gen_hash_dlg.cpp \
    gen_hmac_dlg.cpp \
    gen_otp_dlg.cpp \
    get_ldap_dlg.cpp \
    i18n_helper.cpp \
    insert_data_dlg.cpp \
    key_agree_dlg.cpp \
    key_derive_dlg.cpp \
    main.cpp \
    mainwindow.cpp \
    num_trans_dlg.cpp \
    oid_info_dlg.cpp \
    rsa_enc_dec_dlg.cpp \
    settings_dlg.cpp \
    settings_mgr.cpp \
    sign_verify_dlg.cpp

HEADERS += \
    about_dlg.h \
    auto_update_service.h \
    ber_applet.h \
    ber_define.h \
    ber_item.h \
    ber_item_delegate.h \
    ber_model.h \
    ber_tray_icon.h \
    ber_tree_view.h \
    data_encoder_dlg.h \
    edit_value_dlg.h \
    enc_dec_dlg.h \
    gen_hash_dlg.h \
    gen_hmac_dlg.h \
    gen_otp_dlg.h \
    get_ldap_dlg.h \
    i18n_helper.h \
    insert_data_dlg.h \
    key_agree_dlg.h \
    key_derive_dlg.h \
    mainwindow.h \
    num_trans_dlg.h \
    oid_info_dlg.h \
    rsa_enc_dec_dlg.h \
    settings_dlg.h \
    settings_mgr.h \
    sign_verify_dlg.h \
    singleton.h



# Sparkle.framework 를 Qt/5.11.3/clang_64/lib/ 에 복사 해 주었음

mac {
    ICON = berviewer.icns
    DEFINES += _AUTO_UPDATE
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
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto
    LIBS += -L"/usr/local/lib" -lltdl
}

linux {
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/linux/debug/cmpossl/lib" -lcrypto
    LIBS += -lltdl
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = berviewer.ico
    INCLUDEPATH += "../../PKILib/lib/win32/winsparkle/include"


    LIBS += -L"../../PKILib/lib/win32/winsparkle/Release" -lWinSparkle

    Debug {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto
    }


    LIBS += -L"../../PKILib/lib/win32/ltdl/lib" -lltdl
}

FORMS += \
        about_dlg.ui \
        data_encoder_dlg.ui \
        edit_value_dlg.ui \
        enc_dec_dlg.ui \
        gen_hash_dlg.ui \
        gen_hmac_dlg.ui \
        gen_otp_dlg.ui \
        get_ldap_dlg.ui \
        insert_data_dlg.ui \
        key_agree_dlg.ui \
        key_derive_dlg.ui \
        mainwindow.ui \
        num_trans_dlg.ui \
        oid_info_dlg.ui \
        rsa_enc_dec_dlg.ui \
        settings_dlg.ui \
        sign_verify_dlg.ui

RESOURCES += \
    berviewer.qrc

TRANSLATIONS += i18n/berviewer_ko_KR.ts



target.path = i18n

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target



INCLUDEPATH += "../../PKILib"



DISTFILES +=
