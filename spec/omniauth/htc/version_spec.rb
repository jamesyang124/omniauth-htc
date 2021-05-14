# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../lib/omniauth/htc/version'

describe OmniAuth::Htc do
  it 'has VERSION' do
    expect(OmniAuth::Htc::VERSION).to be_a String
  end

  it 'has mapped gem version as constant VERSION' do
    expect(Gem::Version.correct?(OmniAuth::Htc::VERSION)).to be true
  end
end