Pod::Spec.new do |spec|
  spec.name = "SCrypto"
  spec.version = "1.0.0"
  spec.summary = "The SCrypto framework provides neat Swift API for CommonCrypto routines."
  spec.homepage = "https://github.com/sgl0v/SCrypto"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Maksym Shcheglov" => 'maxscheglov@gmail.com' }
  spec.social_media_url = "http://twitter.com/sgl0v"

  spec.platform = :ios, "9.1"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/sgl0v/SCrypto.git", tag: "v#{spec.version}", submodules: true }
  spec.source_files = "SCrypto/**/*.{h,swift}"

  spec.prepare_command = <<-CMD
    SDKS=( iphoneos iphonesimulator macosx watchsimulator appletvsimulator)
    for sdk in "${SDKS[@]}"
    do
      SDKPATH=$(eval "xcrun -sdk ${sdk} -show-sdk-path")
      mkdir -p "${SDKPATH}/Frameworks/CommonCrypto.framework"

      printf "module CommonCrypto [system] {\n\
      header \"${SDKPATH}/usr/include/CommonCrypto/CommonCrypto.h\"\n\
      header \"${SDKPATH}/usr/include/CommonCrypto/CommonRandom.h\"\n\
      export *\n\
      }" > "${SDKPATH}/System/Library/Frameworks/CommonCrypto.framework/module.map"
    done
  CMD

  # Stop CocoaPods from deleting dummy frameworks
  spec.preserve_paths = "Frameworks"

  # Make sure we can find the dummy frameworks
  spec.xcconfig = { 
  "SWIFT_INCLUDE_PATHS" => "$(SDKROOT)/System/Library/Frameworks",
  "FRAMEWORK_SEARCH_PATHS" => "$(SDKROOT)/System/Library/Frameworks"
  }
end

