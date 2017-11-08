#!/bin/sh

if [ "$#" -eq 1 ]; then
    BASE_DIR=$1
else
	BASE_DIR=$(exec pwd)
fi

SDKS=( iphoneos iphonesimulator macosx watchsimulator appletvsimulator)
SDK_FILE_NAMES=( iPhoneOS.sdk iPhoneSimulator.sdk MacOSX.sdk WatchSimulator.sdk AppleTVSimulator.sdk)

echo "BASE_DIR: ${BASE_DIR}"

for ((i = 0; i < ${#SDKS[@]}; ++i)); do
	SDK="${SDKS[$i]}"
	SDK_FILE_NAME="${SDK_FILE_NAMES[$i]}"
	PLATFORM_PATH=$(eval "xcrun --sdk ${SDK} --show-sdk-platform-path")
	SDK_PATH="${PLATFORM_PATH}/Developer/SDKs/${SDK_FILE_NAME}"

	MODULE_DIR="${BASE_DIR}/Frameworks/${SDK}/CommonCrypto.framework"
  	mkdir -p "${MODULE_DIR}"
	printf "module CommonCrypto [system] {\n\
	header \"${SDK_PATH}/usr/include/CommonCrypto/CommonCrypto.h\"\n\
	header \"${SDK_PATH}/usr/include/CommonCrypto/CommonRandom.h\"\n\
	export *\n\
	}" > "${MODULE_DIR}/module.map"
	echo "Created module map for ${SDK}."
done
