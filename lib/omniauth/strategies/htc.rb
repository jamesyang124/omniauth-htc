# frozen_string_literal: true

require "omniauth"
require "net/https"
require "cgi"

module OmniAuth
  module Strategies
    class Htc
      include OmniAuth::Strategy

      option :auth_host, "account.htcvive.com"
      option :authorize_path, "/SS/api/oauth/v1/authorize"
      option :token_path, "/SS/api/oauth/v2/token/authorization-code"
      option :user_info_host, "account-profile.htcvive.com"
      option :user_info_path, "/SS/Profiles/v3/Me"

      option :client_id
      option :scopes
      option :client_secret
      option :redirection_url

      attr_accessor :access_token, :expires_in

      credentials do
        prune!(
          "token" => access_token,
          "expires_in" => expires_in
        )
      end

      info do
        prune!(
          "uid" => uid,
          "first_name" => raw_info["firstName"],
          "last_name" => raw_info["lastName"]
        )
      end

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

      def sso_auth_uri
        query = sso_auth_params.map { |k,v| to_query k, v }.join("&")

        @sso_auth_uri ||= URI::HTTPS.build(
          host: options.auth_host,
          path: options.authorize_path,
          query: query
        )
      end

      def fetch_access_token(code)
        response = Net::HTTP.post_form(access_token_uri, access_token_params.merge(code: code))

        if response.code_type == Net::HTTPOK
          json = JSON.parse(response.body)
          self.access_token = squish! json["access_token"]
          self.expires_in = json["expires_in"]

          return
        end

        raise OmniAuth::NoSessionError, <<~MSG
          auth code for access token request failed -
          code: #{response.code}
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

        raise OmniAuth::NoSessionError, <<~MSG
          access token get user info request failed -
          token: #{access_token}
          res: #{response.body}
        MSG
      end

      def access_token_uri
        @access_token_uri ||= URI::HTTPS.build(host: options.auth_host, path: options.token_path)
      end

      def user_info_uri
        @user_info_uri ||= URI::HTTPS.build(
          host: options.user_info_host,
          path: options.user_info_path,
          query: "fields=firstName,id,lastName"
        )
      end

      def sso_auth_state_param
        @sso_auth_state_param ||= {
          clientId: options.client_id,
          redirectionUrl: options.redirection_url,
          scopes: options.scopes,
          requireAuthCode: true,
          authorities: "htc.com"
        }.to_json
      end

      def sso_auth_params
        @sso_auth_params ||= {
          client_id: options.client_id,
          redirection_url: options.redirection_url,
          scopes: options.scopes,
          response_type: "code",
          state: sso_auth_state_param
        }
      end

      def access_token_params
        @access_token_params ||= {
          client_id: options.client_id,
          client_secret: options.client_secret,
          grant_type: "authorization_code"
        }
      end

      def to_query(k, v)
        "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}"
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def squish!(str)
        str.gsub!(/\A[[:space:]]+/, '')
        str.gsub!(/[[:space:]]+\z/, '')
        str.gsub!(/[[:space:]]+/, ' ')
      end
    end
  end
end

OmniAuth.config.allowed_request_methods = %i[post get]
