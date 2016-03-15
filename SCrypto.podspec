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

end

