#!/bin/sh
if test "$CONFIGURATION" == 'Deployment'; then

    USER_NAME=keisuke.miyako@4d.com
    UUID=`uuidgen | tr -d - | tr -d '\n' | tr '[:upper:]' '[:lower:]'`
    DEVELOPER_ID=`security find-identity -p codesigning -v | egrep 'Developer ID Application[^"]+' -o`
    PRODUCT_PATH="$CODESIGNING_FOLDER_PATH"
    
    #clean
    xattr -cr "$PRODUCT_PATH"
    codesign --remove-signature "$PRODUCT_PATH"
    
    #sign
    codesign --verbose --deep --timestamp --force --sign "Developer ID Application: keisuke miyako (Y69CWUC25B)" "$PRODUCT_PATH"
    
    #archive
    DMG_PATH="$PROJECT_DIR/$PRODUCT_NAME.dmg"
    ZIP_PATH="$PROJECT_DIR/$PRODUCT_NAME.zip" #for windows
    rm -f "$DMG_PATH"
    hdiutil create -format UDBZ -plist -srcfolder "$PRODUCT_PATH" "$DMG_PATH"
    rm -f "$ZIP_PATH"
    ditto -c -k --keepParent "$PRODUCT_PATH" "$ZIP_PATH"
    
    xcrun notarytool submit "$ZIP_PATH" --keychain-profile "notarytool" --wait
    xcrun notarytool submit "$DMG_PATH" --keychain-profile "notarytool" --wait
        
    xcrun stapler staple "$DMG_PATH"

else
    echo "No notarization performed as this is not a release build."
fi



