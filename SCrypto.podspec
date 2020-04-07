Pod::Spec.new do |spec|
  spec.name = "SCrypto"
  spec.version = "4.0.2"
  spec.summary = "The SCrypto framework provides neat Swift API for CommonCrypto routines."
  spec.homepage = "https://github.com/sgl0v/SCrypto"
  spec.license = { type: 'MIT', file: 'LICENSE' }
  spec.authors = { "Maksym Shcheglov" => 'maxscheglov@gmail.com' }
  spec.social_media_url = "http://twitter.com/sgl0v"

  spec.osx.deployment_target = '10.11'
  spec.ios.deployment_target = '9.0'

  spec.swift_version = '5.0'
  spec.requires_arc = true
  spec.source = { git: "https://github.com/sgl0v/SCrypto.git", tag: spec.version.to_s, submodules: true }
  spec.source_files = "Source/**/*.{h,swift}"
end
