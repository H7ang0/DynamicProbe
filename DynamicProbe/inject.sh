#!/bin/bash

APP_PATH=$1
DYLIB_NAME="DynamicProbe.dylib"
FRIDA_GADGET="frida-gadget.dylib"

if [ -z "$APP_PATH" ]; then
    exit 1
fi

make clean
make dylib

WORK_DIR=$(mktemp -d)
cp -r "$APP_PATH" "$WORK_DIR/"
APP_NAME=$(basename "$APP_PATH")
WORK_APP="$WORK_DIR/$APP_NAME"

mkdir -p "$WORK_APP/Frameworks"

cp ".theos/DynamicProbe/$DYLIB_NAME" "$WORK_APP/Frameworks/"
cp "$FRIDA_GADGET" "$WORK_APP/Frameworks/" 2>/dev/null

BINARY_NAME=$(defaults read "$WORK_APP/Info.plist" CFBundleExecutable)
BINARY_PATH="$WORK_APP/$BINARY_NAME"

install_name_tool -add_rpath "@executable_path/Frameworks" "$BINARY_PATH"

INJECT_LC_LOAD_DYLIB=1
if [ $INJECT_LC_LOAD_DYLIB -eq 1 ]; then
    insert_dylib --all-yes "@rpath/$DYLIB_NAME" "$BINARY_PATH"
fi

codesign -fs "iPhone Developer" --entitlements ent.xml "$WORK_APP/Frameworks/$DYLIB_NAME"
[ -f "$WORK_APP/Frameworks/$FRIDA_GADGET" ] && codesign -fs "iPhone Developer" --entitlements ent.xml "$WORK_APP/Frameworks/$FRIDA_GADGET"
codesign -fs "iPhone Developer" --entitlements ent.xml "$WORK_APP"

cd "$WORK_DIR"
mkdir Payload
mv "$APP_NAME" Payload/
zip -qr "../patched.ipa" Payload

rm -rf "$WORK_DIR"