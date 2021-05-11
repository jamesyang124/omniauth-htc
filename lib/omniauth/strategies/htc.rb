# frozen_string_literal: true

require "omniauth"
require "net/https"

module OmniAuth
  module Strategies
    class Htc
      include OmniAuth::Strategy

      option :authorize_path, "/SS/api/oauth/v1/authorize"
      option :access_token_path, "/SS/api/oauth/v2/token/authorization-code"
      option :user_info_path, "/SS/Profiles/v3/Me"
      option :user_info_host, "profiledev.htcwowdev.com"
      option :authorize_params, {}
      option :authorize_options, %w[client_id scope client_secret redirection_url]

      attr_accessor :access_token, :account_id

      credentials { request.params }
      info { raw_info }
      uid { raw_info["id"] }

      def request_phase
        redirect sso_auth_uri.to_s
      end

      def callback_phase
        fetch_access_token request.params["code"]
        super
      end

      protected

      def raw_info
        @raw_info ||= fetch_user_info
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
          query: "fields=firstName,id,lastName"
        )
      end

      def sso_auth_state_param
        @sso_auth_state_param ||= {
          clientId: options.authorize_options[:client_id],
          redirectionUrl: options.authorize_options[:redirection_url],
          scopes: options.authorize_options[:scope],
          requireAuthCode: true,
          authorities: "htc.com"
        }.to_json
      end

      def sso_auth_params
        @sso_auth_params ||= {
          client_id: options.authorize_options[:client_id],
          redirection_url: options.authorize_options[:redirection_url],
          scopes: options.authorize_options[:scope],
          response_type: "code",
          state: sso_auth_state_param
        }
      end

      def sso_auth_uri
        @sso_auth_uri ||= URI::HTTPS.build(
          host: options[:be_host],
          path: options[:authorize_path],
          query: @sso_auth_params.to_query
        )
      end

      def access_token_params
        @access_token_params ||= {
          client_id: options.authorize_options[:client_id],
          client_secret: options.authorize_options[:client_secret],
          grant_type: "authorization_code"
        }
      end

      def fetch_access_token(code)
        response = Net::HTTP.post_form(access_token_uri, access_token_params.merge(code: code))

        if response.code_type == Net::HTTPOK
          json = JSON.parse(response.body)
          self.access_token = json["access_token"]
          self.account_id = json["account_id"]

          return
        end

        raise OmniAuth::Error, <<~MSG
          auth code for access token request failed -
          code: #{request_body.code}
          res: #{response.body}
        MSG
      end

      def fetch_user_info
        response = Net::HTTP.start(user_info_uri.host, user_info_uri.port, use_ssl: true) do |http|
          req = Net::HTTP::Get.new user_info_uri
          req["authkey"] = access_token

          http.request req
        end

        return JSON.parse(response.body) if response.code_type == Net::HTTPOK

        raise OmniAuth::Error, <<~MSG
          access token get user info request failed -
          token: #{access_token}
          res: #{response.body}
        MSG
      end
    end
  end
end
