# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'omniauth_htc'
require 'faker'

describe OmniAuth::Strategies::Htc do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end

  let(:input_options) do
    {
      client_id: Faker::Internet.uuid,
      scope: 'email',
      client_secret: Faker::String.random,
      redirection_url: Faker::Internet.url
    }
  end

  subject do
    OmniAuth::Strategies::Htc.new(app, input_options).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end

  describe '#identity provider pre-configured options' do
    it 'has pre-configured user info api host' do
      expect(subject.options.auth_host).to be 'account.htcvive.com'
    end

    it 'has pre-configured authorize api path' do
      expect(subject.options.authorize_path).to be '/SS/api/oauth/v2/authorize'
    end

    it 'has pre-configured access token api path' do
      expect(subject.options.token_path).to be '/SS/api/oauth/v2/token/authorization-code'
    end

    it 'has pre-configured user info api host' do
      expect(subject.options.user_info_host).to be 'account-profile.htcvive.com'
    end

    it 'has pre-configured user info api path' do
      expect(subject.options.user_info_path).to be '/SS/Profiles/v3/Me'
    end
  end

  describe '#supply expected input options' do
    it 'has expected input valie as client_id option' do
      expect(subject.options.client_id).to be input_options[:client_id]
    end

    it 'has expected input valie as client_secret option' do
      expect(subject.options.client_secret).to be input_options[:client_secret]
    end

    it 'has expected input valie as scope option' do
      expect(subject.options.scope).to be input_options[:scope]
    end

    it 'has expected input valie as redirection_url option' do
      expect(subject.options.redirection_url).to be input_options[:redirection_url]
    end
  end
end