#-------------------------------------------------
#
# Project created by QtCreator 2019-08-07T14:16:42
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = BerViewer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11


SOURCES += \
    ber_applet.cpp \
        ber_item.cpp \
        ber_item_delegate.cpp \
        ber_model.cpp \
        ber_tree_view.cpp \
        dumpasn1.c \
 #       js_bin.c \
    insert_data_dlg.cpp \
        main.cpp \
        mainwindow.cpp

HEADERS += \
    ber_applet.h \
        ber_item.h \
        ber_item_delegate.h \
        ber_model.h \
        ber_tree_view.h \
#        js_bin.h \
    insert_data_dlg.h \
        mainwindow.h

FORMS += \
        insert_data_dlg.ui \
        mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    berviewer.qrc

LIBS += -lc


INCLUDEPATH += "../../PKILib"
LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
