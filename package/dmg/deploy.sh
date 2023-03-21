#!/bin/bash


BIN_NAME="BerEditor"
APP_NAME="$BIN_NAME/$BIN_NAME.app" 
DEPLOY_CMD="~/Qt/5.15.2/clan_64/bin/macdeploy"

OPENSSL_SRC_PATH="~/work/PKILib/lib/mac/openssl3/lib"
OPENSSL_ORG_PATH="/Users/jykim/work/openssl3/debug"

echo "==========================================="
echo "== $BIN_NAME Deploy"
echo "==========================================="

$DEPLOY_CMD "./$APP_NAME"

otool -L "$APP_NAME/Contents/MacOS/$BIN_NAME"

cp "$OPENSSL_SRC_PATH/libcrypto.3.dylib $APP_NAME/Contents/Frameworks/"
cp "$OPENSSL_SRC_PATH/libssl.3.dylib $APP_NAME/Contents/Frameworks/"

install_name_tool -change "$OPENSSL_ORG_PATH/libcrypto.3.dylib @executable_path/../Frameworks/libcrypto.3.dylib $APP_NAME/Contents/MacOS/$BIN_NAME"
install_name_tool -change "$OPENSSL_ORG_PATH/libssl.3.dylib @executable_path/../Frameworks/libssl.3.dylib $APP_NAME/Contents/MacOS/$BIN_NAME"

echo "== $BIN_NAME Deploy Done"
