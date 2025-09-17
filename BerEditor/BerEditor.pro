#-------------------------------------------------
#
# Project created by QtCreator 2019-08-07T14:16:42
#
#-------------------------------------------------

QT       += core gui network xml

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

requires(qtConfig(filedialog))
qtHaveModule(printsupport): QT += printsupport

TARGET = BerEditor
TEMPLATE = app
PROJECT_VERSION = "2.4.4"

QMAKE_CXXFLAGS += -std=c++17

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += BER_EDITOR_VERSION=$$PROJECT_VERSION
#DEFINES += _AUTO_UPDATE
DEFINES += USE_OCSP
DEFINES += _USE_LCN_SRV

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
    cert_info_dlg.cpp \
    cert_pvd_dlg.cpp \
    pkcs7_dlg.cpp \
    common.cpp \
    crl_info_dlg.cpp \
    data_converter_dlg.cpp \
    dumpasn1.c \
    edit_value_dlg.cpp \
    enc_dec_dlg.cpp \
    gen_hash_dlg.cpp \
    gen_mac_dlg.cpp \
    gen_otp_dlg.cpp \
    get_uri_dlg.cpp \
    i18n_helper.cpp \
    make_ber_dlg.cpp \
    decode_data_dlg.cpp \
    key_agree_dlg.cpp \
    key_man_dlg.cpp \
    lcn_info_dlg.cpp \
    main.cpp \
    mainwindow.cpp \
    num_converter_dlg.cpp \
    oid_info_dlg.cpp \
    pub_enc_dec_dlg.cpp \
    settings_dlg.cpp \
    settings_mgr.cpp \
    sign_verify_dlg.cpp \
    ssl_check_dlg.cpp \
    sss_dlg.cpp \
    csr_info_dlg.cpp \
    vid_dlg.cpp \
    make_value_dlg.cpp \
    bn_calc_dlg.cpp \
    key_pair_man_dlg.cpp \
    gen_key_pair_dlg.cpp \
    make_csr_dlg.cpp \
    ocsp_client_dlg.cpp \
    tsp_client_dlg.cpp \
    tst_info_dlg.cpp \
    cmp_client_dlg.cpp \
    scep_client_dlg.cpp \
    cert_man_dlg.cpp \
    passwd_dlg.cpp \
    new_passwd_dlg.cpp \
    hash_thread.cpp \
    mac_thread.cpp \
    enc_dec_thread.cpp \
    sign_verify_thread.cpp \
    decode_ttlv_dlg.cpp \
    edit_ttlv_dlg.cpp \
    ttlv_client_dlg.cpp \
    ttlv_encoder_dlg.cpp \
    ttlv_tree_item.cpp \
    ttlv_tree_model.cpp \
    ttlv_tree_view.cpp \
    make_ttlv_dlg.cpp \
    pri_key_info_dlg.cpp \
    name_dlg.cpp \
    ldt_hash_thread.cpp \
    cms_info_dlg.cpp \
    content_main.cpp \
    export_dlg.cpp \
    link_man_dlg.cpp \
    find_dlg.cpp \
    key_list_dlg.cpp \
    key_add_dlg.cpp \
    code_editor.cpp \
    cavp_dlg.cpp \
    cavp_dlg2.cpp \
    x509_compare_dlg.cpp \
    cert_id_dlg.cpp \
    acme_client_dlg.cpp \
    acme_object.cpp \
    json_tree_dlg.cpp \
    revoke_reason_dlg.cpp \
    chall_test_dlg.cpp \
    one_list_dlg.cpp \
    two_list_dlg.cpp \
    doc_signer_dlg.cpp \
    time_stamp_dlg.cpp


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
    pkcs7_dlg.h \
    common.h \
    crl_info_dlg.h \
    data_converter_dlg.h \
    edit_value_dlg.h \
    enc_dec_dlg.h \
    gen_hash_dlg.h \
    gen_mac_dlg.h \
    gen_otp_dlg.h \
    get_uri_dlg.h \
    i18n_helper.h \
    make_ber_dlg.h \
    decode_data_dlg.h \
    key_agree_dlg.h \
    key_man_dlg.h \
    lcn_info_dlg.h \
    mainwindow.h \
    num_converter_dlg.h \
    oid_info_dlg.h \
    pub_enc_dec_dlg.h \
    settings_dlg.h \
    settings_mgr.h \
    sign_verify_dlg.h \
    singleton.h \
    ssl_check_dlg.h \
    sss_dlg.h \
    csr_info_dlg.h \
    vid_dlg.h \
    make_value_dlg.h \
    bn_calc_dlg.h \
    key_pair_man_dlg.h \
    gen_key_pair_dlg.h \
    make_csr_dlg.h \
    ocsp_client_dlg.h \
    tsp_client_dlg.h \
    tst_info_dlg.h \
    cmp_client_dlg.h \
    scep_client_dlg.h \
    cert_man_dlg.h \
    passwd_dlg.h \
    new_passwd_dlg.h \
    hash_thread.h \
    mac_thread.h \
    enc_dec_thread.h \
    sign_verify_thread.h \
    decode_ttlv_dlg.h \
    edit_ttlv_dlg.h \
    ttlv_client_dlg.h \
    ttlv_encoder_dlg.h \
    ttlv_tree_item.h \
    ttlv_tree_model.h \
    ttlv_tree_view.h \
    make_ttlv_dlg.h \
    pri_key_info_dlg.h \
    name_dlg.h \
    ldt_hash_thread.h \
    cms_info_dlg.h \
    content_main.h \
    export_dlg.h \
    link_man_dlg.h \
    find_dlg.h \
    key_list_dlg.h \
    key_add_dlg.h \
    code_editor.h \
    cavp_dlg.h \
    x509_compare_dlg.h \
    cert_id_dlg.h \
    acme_client_dlg.h \
    acme_object.h \
    json_tree_dlg.h \
    revoke_reason_dlg.h \
    chall_test_dlg.h \
    one_list_dlg.h \
    two_list_dlg.h \
    doc_signer_dlg.h \
    time_stamp_dlg.h



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
    LIBS += -lxmlsec1 -lxmlsec1-openssl -lxml2
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = bereditor.ico

    message( "64bit" );
    INCLUDEPATH += "../../lib/win64/winsparkle/include"
    INCLUDEPATH += "../../lib/win64/podofo/include"
    INCLUDEPATH += "C:/msys64/mingw64/include"

    Debug {
        LIBS += -L"../../PKILib/build/Desktop_Qt_5_15_2_MinGW_64_bit-Debug -lPKILib"
        LIBS += -L"../../lib/win64/debug/openssl3/lib64 -lcrypto -lssl"
    } else {
        LIBS += -L"../../PKILib/build/Desktop_Qt_5_15_2_MinGW_64_bit-Release -lPKILib"
        LIBS += -L"../../lib/win64/openssl3/lib64 -lcrypto -lssl"
    }

    LIBS += -L"../../lib/win64/xmlsec1/xmlsec/bin -lxmlsec -lxmlsec-openssl"
    LIBS += -L"../../lib/win64/xmlsec1/libxml2/bin -lxml2"
    LIBS += -L"../../lib/win64/xmlsec1/libxslt/bin -lxslt"
    LIBS += -L"../../lib/win64/podofo/bin" -lpodofo
    LIBS += -L"../../lib/win64 -lltdl -lldap -llber"
    LIBS += -L"../../lib/win64/winsparkle/lib -lWinSparkle"
    LIBS += -lws2_32
}

FORMS += \
        about_dlg.ui \
        cavp_dlg.ui \
        cert_info_dlg.ui \
        cert_pvd_dlg.ui \
        pkcs7_dlg.ui \
        crl_info_dlg.ui \
        data_converter_dlg.ui \
        edit_value_dlg.ui \
        enc_dec_dlg.ui \
        gen_hash_dlg.ui \
        gen_mac_dlg.ui \
        gen_otp_dlg.ui \
        get_uri_dlg.ui \
        make_ber_dlg.ui \
        decode_data_dlg.ui \
        key_agree_dlg.ui \
        key_man_dlg.ui \
        lcn_info_dlg.ui \
        mainwindow.ui \
        num_converter_dlg.ui \
        oid_info_dlg.ui \
        pub_enc_dec_dlg.ui \
        settings_dlg.ui \
        sign_verify_dlg.ui \
        ssl_check_dlg.ui \
        sss_dlg.ui \
        csr_info_dlg.ui \
        vid_dlg.ui \
        make_value_dlg.ui \
        bn_calc_dlg.ui \
        key_pair_man_dlg.ui \
        gen_key_pair_dlg.ui \
        make_csr_dlg.ui \
        ocsp_client_dlg.ui \
        tsp_client_dlg.ui \
        tst_info_dlg.ui \
        cmp_client_dlg.ui \
        scep_client_dlg.ui \
        cert_man_dlg.ui \
        passwd_dlg.ui \
        new_passwd_dlg.ui \
        ttlv_client_dlg.ui \
        ttlv_encoder_dlg.ui \
        decode_ttlv_dlg.ui \
        edit_ttlv_dlg.ui \
        make_ttlv_dlg.ui \
        pri_key_info_dlg.ui \
        name_dlg.ui \
        cms_info_dlg.ui \
        content_main.ui \
        export_dlg.ui \
        link_man_dlg.ui \
        find_dlg.ui \
        key_list_dlg.ui \
        key_add_dlg.ui \
        cavp_dlg.ui \
        x509_compare_dlg.ui \
        cert_id_dlg.ui \
        acme_client_dlg.ui \
        json_tree_dlg.ui \
        revoke_reason_dlg.ui \
        chall_test_dlg.ui \
        one_list_dlg.ui \
        two_list_dlg.ui \
        doc_signer_dlg.ui \
        time_stamp_dlg.ui

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
