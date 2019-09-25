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
PARAFFIN=/home/jykim/bin/Paraffin.exe

CFLAGS = -ext WixUIExtension -ext WixUtilExtension
LDFLAGS = -spdb -ext WixUIExtension -ext WixUtilExtension \
		-loc ${LANG_FILE} -cultures:${CULTURE} -sice:ICE80

sources = WixUI_InstallDir_NoLicense.wxs MyInstallDirDlg.wxs fragment.wxs BerViewer.wxs

OBJECTS = ${sources:%.wxs=%.wixobj}

fragment.wxs:
	$(PARAFFIN) -dir ./BerViewer -gn group_bin -alias bin fragment.wxs
	cp -rf ./BerViewer/* ./bin

%.wixobj : %.wxs
	$(CC) $(CFLAGS) $< -o $@

BerViewer.wixobj : Berviewer.wxs Includes.wxi
	$(CC) $(CFLAGS) $< -o $@

$(TARGET) : $(OBJECTS) $(LANG_FILE)
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

clean :
	rm -f $(OBJECTS) *.msi fragment.*

rmbin :
	rm -f *.msi *.wixobj

.PHONY: all en ko clean
