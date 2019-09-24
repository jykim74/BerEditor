CULTURE = ko-kr
LANG_FILE = ko_KR.wxl
TARGET = berViewer-ko.msi

ifeq (${MAKECMDGOALS}, en)
	CULTURE = en-us
	LANG_FILE = en_US.wxl
	TARGET = berViewer-en.msi
endif

all: $(TARGET)
en: all
ko: all

CC=/home/jykim/bin/wix/candle.exe
LD=/home/jykim/bin/wix/light.exe

CFLAGS = -nolog -ext WixUIExtension -ext WixUtilExtension
LDFLAGS = -nolog -spdb -ext WixUIExtension -ext WixUtilExtension \
		-loc ${LANG_FILE} -cultures:${CULTURE} -sice:ICE80

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs fragment.wxs BerViewer.wxs
