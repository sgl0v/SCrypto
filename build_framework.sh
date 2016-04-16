#!/bin/sh

BASE_DIR="`dirname \"$0\"`"
BUILD_DIR="@{BASE_DIR}/build"
PROJECT_DIR=$BASE_DIR
PROJECT_NAME=SCrypto
WORKSPACE="${PROJECT_NAME}.xcworkspace"
SCHEME="${PROJECT_NAME} iOS"
CONFIGURATION=Release

function usage()
{
    echo "The build script for iOS universal framework."
    echo ""
    echo "./build_framework.sh"
    echo "\t-h --help"
    echo "\t--scheme=$SCHEME"
    echo "\t--configuration=$CONFIGURATION"
    echo ""
}

while [ "$1" != "" ]; do
    PARAM=`echo $1 | awk -F= '{print $1}'`
    VALUE=`echo $1 | awk -F= '{print $2}'`
    case $PARAM in
        -h | --help)
            usage
            exit
            ;;
        --scheme)
            SCHEME=$VALUE
            ;;
        --configuration)
            CONFIGURATION=$VALUE
            ;;
        *)
            echo "ERROR: unknown parameter \"$PARAM\""
            usage
            exit 1
            ;;
    esac
    shift
done

UNIVERSAL_OUTPUTFOLDER=${BUILD_DIR}/${CONFIGURATION}-universal

# exit the script if any statement returns a non-true return value. 
set -o pipefail

# make sure the output directory exists
mkdir -p "${UNIVERSAL_OUTPUTFOLDER}"

echo "Building the Device and Simulator versions \xF0\x9F\x8D\xBA"

# Step 1. Build Device and Simulator versions
xcodebuild -workspace "$WORKSPACE" -scheme "$SCHEME" -configuration ${CONFIGURATION} -sdk iphoneos  ONLY_ACTIVE_ARCH=NO BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${PROJECT_DIR}" clean build  > /dev/null
xcodebuild -workspace "$WORKSPACE" -scheme "$SCHEME" -configuration ${CONFIGURATION} -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO BUILD_DIR="${BUILD_DIR}" BUILD_ROOT="${PROJECT_DIR}" clean build  > /dev/null

echo "Creating the universal framework..."

# Step 2. Copy the framework structure (from iphoneos build) to the universal folder
cp -R "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${PROJECT_NAME}.framework" "${UNIVERSAL_OUTPUTFOLDER}/"

# Step 3. Copy Swift modules from iphonesimulator build (if it exists) to the copied framework directory
SIMULATOR_SWIFT_MODULES_DIR="${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${PROJECT_NAME}.framework/Modules/${PROJECT_NAME}.swiftmodule/."
if [ -d "${SIMULATOR_SWIFT_MODULES_DIR}" ]; then
cp -R "${SIMULATOR_SWIFT_MODULES_DIR}" "${UNIVERSAL_OUTPUTFOLDER}/${PROJECT_NAME}.framework/Modules/${PROJECT_NAME}.swiftmodule"
fi

# Step 4. Create universal binary file using lipo and place the combined executable in the copied framework directory
lipo -create -output "${UNIVERSAL_OUTPUTFOLDER}/${PROJECT_NAME}.framework/${PROJECT_NAME}" "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${PROJECT_NAME}.framework/${PROJECT_NAME}" "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${PROJECT_NAME}.framework/${PROJECT_NAME}"

# Step 5. Convenience step to open the project's directory in Finder
open "${UNIVERSAL_OUTPUTFOLDER}"

echo "Done!"
