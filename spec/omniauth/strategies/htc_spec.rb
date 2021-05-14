# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'omniauth_htc'

describe OmniAuth::Strategies::Htc do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end

  subject do
    OmniAuth::Strategies::Htc.new(app, {}).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end

  describe '#identity provider pre-configured options' do
    it 'has pre-configured authorize api path' do
      expect(subject.options.authorize_path).to be '/SS/api/oauth/v2/authorize'
    end

    it 'has pre-configured access token api path' do
      expect(subject.options.access_token_path).to be '/SS/api/oauth/v2/token/authorization-code'
    end

    it 'has pre-configured user info api path' do
      expect(subject.options.user_info_path).to be '/SS/Profiles/v3/Me'
    end

    it 'has pre-configured user info api host' do
      expect(subject.options.user_info_host).to be 'profiledev.htcwowdev.com'
    end
  end
end