# frozen_string_literal: true

require_relative "lib/omniauth/htc/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-htc"
  spec.version       = OmniAuth::Htc::VERSION
  spec.authors       = ["James Yang"]
  spec.email         = ["jamesyang124@gmail.com"]

  spec.summary       = "OmniAuth stratgey for single sign on with HTC"
  spec.description   = "OmniAuth stratgey for single sign on with HTC"
  spec.homepage      = "https://github.com/jamesyang124/omniauth-htc"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.7.0")
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "https://github.com/jamesyang124/omniauth-htc/blob/master/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "omniauth", "~> 1.0"

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.10"
  spec.add_development_dependency "rubocop", "~> 1.7"
  spec.add_development_dependency "faker", "~> 2.0"
  spec.add_development_dependency "webmock", "~> 3.0"
end
