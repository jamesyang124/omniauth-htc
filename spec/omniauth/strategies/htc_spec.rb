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
      scopes: 'email+profile',
      client_secret: Faker::String.random,
      redirection_url: Faker::Internet.url
    }
  end

  after do
    WebMock.reset!
  end

  subject do
    OmniAuth::Strategies::Htc.new(app, input_options).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end

  describe '#options should have identity provider options' do
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

  describe '#options should have client options' do
    it 'has expected input valie as client_id option' do
      expect(subject.options.client_id).to be input_options[:client_id]
    end

    it 'has expected input valie as client_secret option' do
      expect(subject.options.client_secret).to be input_options[:client_secret]
    end

    it 'has expected input valie as scope option' do
      expect(subject.options.scopes).to be input_options[:scopes]
    end

    it 'has expected input valie as redirection_url option' do
      expect(subject.options.redirection_url).to be input_options[:redirection_url]
    end
  end

  describe '#reques_phase should redirect to htc identity oauth auth url' do
    before do
      @subject = subject
      @request = subject.request_phase
      @redirect_url = URI.parse(@request[1]['Location'])
      @query = CGI.parse(@redirect_url.query)
    end

    it 'redirect to htc identity oauth auth url with proper http status code' do
      expect(@request[0]).to be 302
    end

    it 'redirect to htc identity oauth auth url with proper host and path' do
      expect(@redirect_url.host).to eq(@subject.options.auth_host)
      expect(@redirect_url.path).to eq(@subject.options.authorize_path)
    end

    it 'redirect to htc identity oauth auth url with proper first-level query params' do
      %w(client_id scopes redirection_url).each do |v|
        expect(@query[v]).to eq([input_options[v.to_sym]])
      end

      expect(@query['response_type']).to eq(['code'])
    end

    it 'redirect to htc identity oauth auth url with proper state query param' do
      expect(@query['state']).to eq([{
        clientId: input_options[:client_id],
        redirectionUrl: input_options[:redirection_url],
        scopes: input_options[:scopes],
        requireAuthCode: true,
        authorities: "htc.com"
      }.to_json])
    end
  end
end