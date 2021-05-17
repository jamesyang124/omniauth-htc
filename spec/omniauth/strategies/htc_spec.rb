# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'omniauth_htc'
require 'faker'

describe OmniAuth::Strategies::Htc do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) { lambda { |_env| [200, {}, ['Hello.']] } }

  let(:input_options) do
    {
      client_id: Faker::Internet.uuid,
      scopes: 'email+profile',
      client_secret: Faker::String.random,
      redirection_url: Faker::Internet.url
    }
  end

  let(:access_token) do
    {
      client_id: Faker::Internet.uuid,
      access_token: Faker::String.random,
      account_id: Faker::Internet.uuid,
      expires_in: 600,
      scope: "email+profile",
      token_type: "bearer"
    }
  end

  let(:user_info) do
    {
      id: Faker::Internet.uuid,
      firstName: Faker::Name::first_name,
      lastName: Faker::Name::last_name
    }
  end

  subject do
    OmniAuth::Strategies::Htc.new(app, input_options).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end

      allow(strategy).to receive(:env).and_return(make_env)
    end
  end

  after do
    WebMock.reset!
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
    it 'have expected input valie as client_id option' do
      expect(subject.options.client_id).to be input_options[:client_id]
    end

    it 'have expected input valie as client_secret option' do
      expect(subject.options.client_secret).to be input_options[:client_secret]
    end

    it 'have expected input valie as scope option' do
      expect(subject.options.scopes).to be input_options[:scopes]
    end

    it 'have expected input valie as redirection_url option' do
      expect(subject.options.redirection_url).to be input_options[:redirection_url]
    end
  end

  describe '#request_phase should redirect to htc identity oauth auth url' do
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

  describe '#callback_phase should grant access token and user info' do
    it 'get access token from auth code respond bad request error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(status: 400, body: Faker::String.random)

      err_msg_reg = /auth code for access token request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get access token from auth code respond internal server error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(status: 500, body: Faker::String.random)

      err_msg_reg = /auth code for access token request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get access token from auth code respond empty lead JSON parse error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(status: 200, body: nil)

      expect { subject.callback_phase }.to raise_error(JSON::ParserError)
    end

    it 'get access token from auth code respond no-content http status code' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(status: 204, body: nil)

      err_msg_reg = /auth code for access token request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get user info respond bad request error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(body: access_token.to_json)

      user_info_url = 'https://account-profile.htcvive.com/SS/Profiles/v3/Me?fields=firstName,id,lastName'
      stub_request(:get, user_info_url).to_return(status: 400, body: Faker::String.random)

      err_msg_reg = /access token get user info request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get user info respond internal server error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(body: access_token.to_json)

      user_info_url = 'https://account-profile.htcvive.com/SS/Profiles/v3/Me?fields=firstName,id,lastName'
      stub_request(:get, user_info_url).to_return(status: 500, body: Faker::String.random)

      err_msg_reg = /access token get user info request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get user info respond no-content http status code' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(body: access_token.to_json)

      user_info_url = 'https://account-profile.htcvive.com/SS/Profiles/v3/Me?fields=firstName,id,lastName'
      stub_request(:get, user_info_url).to_return(status: 204, body: nil)

      err_msg_reg = /access token get user info request failed -/
      expect { subject.callback_phase }.to raise_error(OmniAuth::NoSessionError, err_msg_reg)
    end

    it 'get user info respond empty lead JSON parse error' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(body: access_token.to_json)

      user_info_url = 'https://account-profile.htcvive.com/SS/Profiles/v3/Me?fields=firstName,id,lastName'
      stub_request(:get, user_info_url).to_return(status: 200, body: nil)

      expect { subject.callback_phase }.to raise_error(JSON::ParserError)
    end

    it 'get user_info and grant access token from auth code succeed' do
      token_url = 'https://account.htcvive.com/SS/api/oauth/v2/token/authorization-code'
      stub_request(:post, token_url).to_return(body: access_token.to_json)

      user_info_url = 'https://account-profile.htcvive.com/SS/Profiles/v3/Me?fields=firstName,id,lastName'
      stub_request(:get, user_info_url).to_return(body: user_info.to_json)

      subject.callback_phase

      expect_info = {
        "first_name" => user_info[:firstName],
        "last_name" => user_info[:lastName],
        "uid" => user_info[:id]
      }

      expect_credentials = {
        "token" => squish!(access_token[:access_token]),
        "expires_in" => access_token[:expires_in],
      }

      expect(subject.uid).to eq(user_info[:id])
      expect(subject.info).to eq(expect_info)
      expect(subject.env["omniauth.auth"]["provider"]).to eq "htc"
      expect(subject.env["omniauth.auth"]["uid"]).to eq user_info[:id]
      expect(subject.env["omniauth.auth"]["info"]).to eq expect_info
      expect(subject.env["omniauth.auth"]["credentials"]).to eq expect_credentials
      expect(subject.env["omniauth.auth"]["extra"]).to eq({})
    end
  end
end