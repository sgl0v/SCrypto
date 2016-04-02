Pod::Spec.new do |spec|
  spec.name = "SCrypto"
  spec.version = "1.0.0"
  spec.summary = "The SCrypto framework provides neat Swift API for CommonCrypto routines."
  spec.homepage = "https://github.com/sgl0v/SCrypto"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Maksym Shcheglov" => 'maxscheglov@gmail.com' }
  spec.social_media_url = "http://twitter.com/sgl0v"

  spec.platform = :ios, "9.0"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/sgl0v/SCrypto.git", tag: "v#{spec.version}", submodules: true }
  spec.source_files = "Source/**/*.{h,swift}"

  # Create module.map files for CommonCrypto framework
  spec.preserve_paths = "Frameworks"
  spec.prepare_command = <<-CMD
  BASE_DIR=$(exec pwd)
  echo "BASE_DIR: ${BASE_DIR}"
  SDKS=( iphoneos iphonesimulator macosx watchsimulator appletvsimulator)
  for SDK in "${SDKS[@]}"
  do
    MODULE_DIR="${BASE_DIR}/Frameworks/${SDK}/CommonCrypto.framework"
    mkdir -p "${MODULE_DIR}"
    printf "module CommonCrypto [system] {\n\
    header \"${SDKPATH}/usr/include/CommonCrypto/CommonCrypto.h\"\n\
    header \"${SDKPATH}/usr/include/CommonCrypto/CommonRandom.h\"\n\
    export *\n\
    }" > "${MODULE_DIR}/module.map"
    echo "Created module map for ${SDK}."
  done
  CMD

  # add the new module to Import Paths
  spec.xcconfig = { 
  "SWIFT_INCLUDE_PATHS" => "$(PODS_ROOT)/SCrypto/Frameworks/$(PLATFORM_NAME)",
  "FRAMEWORK_SEARCH_PATHS" => "$(PODS_ROOT)/SCrypto/Frameworks/$(PLATFORM_NAME)"
  }

end
