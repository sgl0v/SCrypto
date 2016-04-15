#!/bin/sh

if [ "$#" -eq 2 ]; then
    SDKS=( $1 )
    BASE_DIR=$2
else
	SDKS=( iphoneos iphonesimulator macosx watchsimulator appletvsimulator)
	BASE_DIR=$(exec pwd)
fi

echo "BASE_DIR: ${BASE_DIR}"
for SDK in "${SDKS[@]}"
do
	MODULE_DIR="${BASE_DIR}/Frameworks/${SDK}/CommonCrypto.framework"
	SDKPATH=$(eval "xcrun --sdk ${SDK} --show-sdk-path")
	mkdir -p "${MODULE_DIR}"
	printf "module CommonCrypto [system] {\n\
	header \"${SDKPATH}/usr/include/CommonCrypto/CommonCrypto.h\"\n\
	header \"${SDKPATH}/usr/include/CommonCrypto/CommonRandom.h\"\n\
	export *\n\
	}" > "${MODULE_DIR}/module.map"
	echo "Created module map for ${SDK}."
done
