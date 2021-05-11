# frozen_string_literal: true

require 'omniauth'
require 'net/https'

module OmniAuth
  module Strategies
    class Htc
      include OmniAuth::Strategy

      option :authorize_path, '/SS/api/oauth/v1/authorize'
      option :access_token_path, '/SS/api/oauth/v2/token/authorization-code'

      option :user_info_path, '/SS/Profiles/v3/Me'
      option :user_info_host, 'profiledev.htcwowdev.com'

      option :redirection_url, 'https://www.htcsense.com.local/auth/htcididentity/callback'

      option :client_id
      option :client_secret

      option :scope
      option :authorize_params, {}
      option :authorize_options, %w(client_id scope)

      attr_accessor :access_token, :account_id

      credentials { request.params }
      info { raw_info }
      uid { raw_info['id'] }

      def initialize(app, *args, &block)
        super
      end

      def request_phase
        redirect sso_auth_uri.to_s
      end

      def callback_phase
        get_access_token request.params['code']
        super
      end

      protected

      def raw_info
        @raw_info ||= get_user_info
      end

      def access_token_uri
        @access_token_uri ||= URI::HTTPS.build(
          host: options[:be_host],
          path: options[:access_token_path]
        )
      end

      def user_info_uri
        @user_info_uri ||= URI::HTTPS.build(
          host: options[:user_info_host],
          path: options[:user_info_path],
          query: 'fields=firstName,id,lastName'
        )
      end

      def sso_auth_uri
        return @sso_auth_uri if @sso_auth_uri

        state = {
          clientId: options[:client_id],
          redirectionUrl: options[:redirection_url],
          scopes: options[:scope],
          requireAuthCode: true,
          authorities: 'htc.com'
        }

        query = {
          client_id: options[:client_id],
          scopes: options[:scope],
          state: state.to_json,
          response_type: 'code',
          redirection_url: options[:redirection_url]
        }

        @sso_auth_uri ||= URI::HTTPS.build(
          host: options[:be_host],
          path: options[:authorize_path],
          query: query.to_query
        )
      end

      def get_access_token(code)
        response = Net::HTTP.post_form(access_token_uri,
          client_id: options[:client_id],
          client_secret: options[:client_secret],
          code: code,
          grant_type: 'authorization_code'
        )

        if response.code_type == Net::HTTPOK
          json = JSON.parse(response.body)
          self.access_token = json["access_token"]
          self.account_id = json["account_id"]
        else
          raise OmniAuth::Error.new(<<~EOS)
            auth code for access token request failed -
            code: #{request_body.code}
            req: #{uri}
            res: #{response.body}
          EOS
        end
      end

      def get_user_info
        uri = user_info_uri

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
          req = Net::HTTP::Get.new uri
          req['authkey'] = self.access_token

          http.request req
        end

        if response.code_type == Net::HTTPOK
          @raw_info = JSON.parse(response.body)
        else
          raise OmniAuth::Error.new(<<~EOS)
            access token get user info request failed -
            token: #{self.access_token}
            req: #{uri}
            res: #{response.body}
          EOS
        end

        @raw_info
      end
    end
  end
end

