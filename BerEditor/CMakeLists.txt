cmake_minimum_required(VERSION 3.5)

project(BerEditor
    VERSION 1.8.4
    DESCRIPTION "BerEditor Application"
    LANGUAGES CXX )

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Set up AUTOMOC and some sensible defaults for runtime execution
# When using Qt 6.3, you can replace the code block below with
# qt_standard_project_setup()
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

#add_definitions( -D_USE_RC_LCN )
add_definitions( -D_USE_LCN_SRV )

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS PrintSupport Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Network)

if(APPLE)
    SET(platform_specific_sources ${platform_specific_sources} mac_sparkle_support.mm)
    SET(platform_specific_headers ${platform_specific_headers} mac_sparkle_support.h)
    SET_SOURCE_FILES_PROPERTIES(mac_sparkle_support.mm PROPERTIES COMPILE_FLAGS -fobjc-arc)
    SET(SPARKLE_FRAMEWORK /usr/local/Sparkle.framework)
    INCLUDE_DIRECTORIES(${SPARKLE_FRAMEWORK}/Headers)
endif()

set(PROJECT_SRC
    about_dlg.cpp
    auto_update_service.cpp
    ber_applet.cpp
    ber_item.cpp
    ber_item_delegate.cpp
    ber_model.cpp
    ber_tray_icon.cpp
    ber_tree_view.cpp
    cavp_dlg.cpp
    cert_info_dlg.cpp
    cert_pvd_dlg.cpp
    cms_dlg.cpp
    common.cpp
    crl_info_dlg.cpp
    data_encoder_dlg.cpp
    dumpasn1.c
    edit_value_dlg.cpp
    enc_dec_dlg.cpp
    gen_hash_dlg.cpp
    gen_mac_dlg.cpp
    gen_otp_dlg.cpp
    get_uri_dlg.cpp
    i18n_helper.cpp
    insert_ber_dlg.cpp
    insert_data_dlg.cpp
    key_agree_dlg.cpp
    key_man_dlg.cpp
    lcn_info_dlg.cpp
    main.cpp
    mainwindow.cpp
    num_trans_dlg.cpp
    oid_info_dlg.cpp
    pub_enc_dec_dlg.cpp
    settings_dlg.cpp
    settings_mgr.cpp
    sign_verify_dlg.cpp
    sss_dlg.cpp
    ssl_verify_dlg.cpp
    csr_info_dlg.cpp
    trust_list_dlg.cpp
    vid_dlg.cpp
    make_value_dlg.cpp
    bn_calc_dlg.cpp
    ${platform_specific_sources}
)

set( PROJECT_HEADER
    about_dlg.h
    auto_update_service.h
    ber_applet.h
    ber_item.h
    ber_item_delegate.h
    ber_model.h
    ber_tray_icon.h
    ber_tree_view.h
    cavp_dlg.h
    cert_info_dlg.h
    cert_pvd_dlg.h
    cms_dlg.h
    common.h
    crl_info_dlg.h
    data_encoder_dlg.h
    edit_value_dlg.h
    enc_dec_dlg.h
    gen_hash_dlg.h
    gen_mac_dlg.h
    gen_otp_dlg.h
    get_uri_dlg.h
    i18n_helper.h
    insert_ber_dlg.h
    insert_data_dlg.h
    key_agree_dlg.h
    key_man_dlg.h
    lcn_info_dlg.h
    mainwindow.h
    num_trans_dlg.h
    oid_info_dlg.h
    pub_enc_dec_dlg.h
    settings_dlg.h
    settings_mgr.h
    sign_verify_dlg.h
    singleton.h
    sss_dlg.h
    ssl_verify_dlg.h
    csr_info_dlg.h
    trust_list_dlg.h
    vid_dlg.h
    make_value_dlg.h
    bn_calc_dlg.h
    ${platform_specific_headers}
)

set( PROJECT_FORM
    about_dlg.ui
    cavp_dlg.ui
    cert_info_dlg.ui
    cert_pvd_dlg.ui
    cms_dlg.ui
    crl_info_dlg.ui
    data_encoder_dlg.ui
    edit_value_dlg.ui
    enc_dec_dlg.ui
    gen_hash_dlg.ui
    gen_mac_dlg.ui
    gen_otp_dlg.ui
    get_uri_dlg.ui
    insert_ber_dlg.ui
    insert_data_dlg.ui
    key_agree_dlg.ui
    key_man_dlg.ui
    lcn_info_dlg.ui
    mainwindow.ui
    num_trans_dlg.ui
    oid_info_dlg.ui
    pub_enc_dec_dlg.ui
    settings_dlg.ui
    sign_verify_dlg.ui
    sss_dlg.ui
    ssl_verify_dlg.ui
    csr_info_dlg.ui
    trust_list_dlg.ui
    vid_dlg.ui
    make_value_dlg.ui
    bn_calc_dlg.ui
)


set(PROJECT_SOURCES
    ${PROJECT_SRC} ${PROJECT_HEADER} ${PROJECT_FORM}
)

set(RESOURCE ${CMAKE_SOURCE_DIR}/bereditor.qrc)
qt5_add_resources(RESOURCE_ADDED ${RESOURCE})

add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCES}
    ${RESOURCE_ADDED}
    be.rc
    bereditor.icns
    BerEditor.pro
    ../LICENSE
    key_pair_man_dlg.h key_pair_man_dlg.cpp key_pair_man_dlg.ui
    gen_key_pair_dlg.h gen_key_pair_dlg.cpp gen_key_pair_dlg.ui
    make_csr_dlg.h make_csr_dlg.cpp make_csr_dlg.ui
    ocsp_client_dlg.h ocsp_client_dlg.cpp ocsp_client_dlg.ui
    tsp_client_dlg.h tsp_client_dlg.cpp tsp_client_dlg.ui
)

target_link_options( ${PROJECT_NAME} PRIVATE -mwindows -MD )

# target_compile_definitions( ${PROJECT_NAME} PRIVATE JS_PRO )


if(WIN32)
    include_directories( ../../PKILib
        "c:/msys64/mingw64/include"
        ../../lib/win64/winsparkle/include )

    message( STATUS ${CMAKE_BUILD_TYPE} )


   if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
        ../../lib/win64/debug/openssl3/lib64
        ../../lib/win64/winsparkle/lib
        ../../lib/win64 )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
        ../../lib/win64/openssl3/lib64
        ../../lib/win64/winsparkle/lib
        ../../lib/win64 )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
	Qt${QT_VERSION_MAJOR}::PrintSupport
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber ws2_32 WinSparkle )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(APPLE)
    set(CMAKE_MACOSX_BUNDLE ON)
    set(CMAKE_MACOSX_RPATH ON)

    # The MACOSX_BUNDLE_ICON_FILE variable is added to the Info.plist
    # generated by CMake. This variable contains the .icns file name,
    # without the path.

    # And the following tells CMake where to find and install the file itself.

    set_source_files_properties(bereditor.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources)

    set_target_properties( ${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE true
        MACOSX_BUNDLE_ICON_FILE bereditor.icns
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist )

    include_directories( ../../PKILib
        ../../lib/mac/openssl3/include
        /usr/local/include )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug
        ../../lib/mac/debug/openssl3/lib
        /usr/local/lib )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release
        ../../lib/mac/openssl3/lib
        /usr/local/lib )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
	Qt${QT_VERSION_MAJOR}::PrintSupport
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber
        "-framework AppKit"
        "-framework Carbon"
        "-framework Foundation"
        "-framework ApplicationServices"
        "-framework Sparkle" )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(LINUX)
    include_directories( ../../PKILib

        "/usr/local/include" )

    if(Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug
        ../../lib/win64/debug/openssl3/lib64
        "/usr/local/lib" )
    endif()

    if(NOT Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Release
        ../../PKILib/lib/win64/openssl3/lib64
        "/usr/local/lib" )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
	Qt${QT_VERSION_MAJOR}::PrintSupport
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber )
endif()

target_compile_definitions( ${PROJECT_NAME} PRIVATE
    BER_EDITOR_VERSION=${PROJECT_VERSION}
    QT_DEPRECATED_WARNINGS
)


find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets LinguistTools REQUIRED)
set(TS_FILES bereditor_ko_KR.ts)
#qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
qt5_add_translation( ${PROJECT_NAME} TS_FILES bereditor_ko_KR.ts )

if(WIN32)
    install( TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin )
elseif(APPLE)
    install( TARGETS ${PROJECT_NAME} BUNDLE DESTINATION . RUNTIME DESTINATION . )
elseif(LINUX)
    install( TARGETS ${PROJECT_NAME} RUNTIME_DESTINATION bin )
endif()
