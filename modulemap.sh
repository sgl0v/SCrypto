#!/bin/sh

BASE_DIR=$(exec pwd)
echo "BASE_DIR: ${BASE_DIR}"
SDKS=( iphoneos iphonesimulator macosx watchsimulator appletvsimulator)
for SDK in "${SDKS[@]}"
do
MODULE_DIR="${BASE_DIR}/Frameworks/${SDK}/CommonCrypto.framework"
SDKPATH=$(eval "xcrun --sdk ${SDK} --show-sdk-path")
mkdir -p "${MODULE_DIR}"
echo "module CommonCrypto [system] {\n\
header \"${SDKPATH}/usr/include/CommonCrypto/CommonCrypto.h\"\n\
header \"${SDKPATH}/usr/include/CommonCrypto/CommonRandom.h\"\n\
export *\n\
}" > "${MODULE_DIR}/module.map"
echo "Created module map for ${SDK}."
done
