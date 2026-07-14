# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# frozen_string_literal: true

# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

require 'oci'
require 'openssl'
require 'json'
require 'base64'
require 'net/http'
require 'uri'
require 'cgi'

module OCI
  module Auth
    module Signers
      # rubocop:disable Metrics/ClassLength, Metrics/AbcSize, Metrics/LineLength, Metrics/CyclomaticComplexity, Metrics/ParameterLists
      # Implementation of Resource Principal v2.1.1/v2.1.2 authentication
      class EphemeralResourcePrincipalV21Signer < OCI::Auth::Signers::SecurityTokenSigner
        attr_reader :region
        def initialize(resource_principal_token_endpoint: nil,
                       resource_principal_session_token_endpoint: nil,
                       resource_id: nil,
                       tenancy_id: nil,
                       rp_version: nil,
                       region: nil,
                       security_context: nil,
                       private_key: nil,
                       private_key_passphrase: nil,
                       resource_principal_token_path: nil)

          validate_required_params!(
            resource_principal_token_endpoint,
            resource_principal_session_token_endpoint,
            resource_id,
            tenancy_id,
            rp_version,
            private_key
          )

          @rp_version = rp_version

          @rpt_endpoint = resource_principal_token_endpoint

          @rpst_endpoint = resource_principal_session_token_endpoint

          @resource_id = resource_id

          @region = initialize_and_return_region(region)

          @retry_strategy = OCI::Auth::Util.default_imds_retry_policy
          @tenancy_id = tenancy_id

          @security_context = security_context
          @reset_signers_lock = Mutex.new

          @resource_principal_token_path = if @rp_version == '2.1.2'
                                             build_rpt_path_for_rpv212(resource_principal_token_path, resource_id)
                                           else
                                             "/20180711/resourcePrincipalTokenV2/#{resource_id}"
                                           end

          # Set up session key supplier
          @session_key_supplier = construct_session_key_supplier(private_key,
                                                                 private_key_passphrase)
          @api_client = OCI::ApiClient.new(OCI::Config.new, OCI::Auth::Signers::KeyPairSigner.new(rp_version, resource_id, tenancy_id, @session_key_supplier.key_pair[:private_key]))

          # Get initial tokens
          refresh_security_token

          super(
            @security_token.security_token,
            @session_key_supplier.key_pair[:private_key]
          )
        end

        def security_token
          return @security_token.security_token if @security_token && @security_token.token_valid?

          refresh_security_token
        end

        def refresh_security_token
          @reset_signers_lock.synchronize do
            begin
              # Refresh Session Keys
              @session_key_supplier.refresh

              # Get RPT and SPST
              @rpt, @spst = resource_principal_token_and_service_principal_session_token

              # Get RPST
              @security_token = OCI::Auth::SecurityTokenContainer.new(resource_principal_session_token)

              # Reset Signers
              reset_signers
              @security_token.security_token
            rescue StandardError => e
              raise "Failed to refresh security token: #{e}"
            end
          end
        end

        private

        def construct_session_key_supplier(private_key, private_key_passphrase)
          if File.file?(private_key)
            OCI::Auth::FileSessionKeySupplier.new(
              private_key_file: private_key,
              passphrase_file: private_key_passphrase
            )
          else
            @private_key = OCI::Auth::Util.load_private_key(
              private_key, private_key_passphrase
            )
            OCI::Auth::FixedSessionKeySupplier.new(private_key: @private_key)
          end
        end

        def validate_required_params!(rpt_endpoint, rpst_endpoint, resource_id, tenancy_id, rp_version, private_key)
          raise ArgumentError, 'resource_principal_token_endpoint is required' unless rpt_endpoint
          raise ArgumentError, 'resource_principal_session_token_endpoint is required' unless rpst_endpoint
          raise ArgumentError, 'resource_id is required' unless resource_id
          raise ArgumentError, 'tenancy_id is required for rp_version 2.1.1 or 2.1.2' if %w[2.1.1 2.1.2].include?(rp_version) && tenancy_id.nil?
          raise ArgumentError, 'private_key is required' unless private_key
        end

        def resource_principal_token_and_service_principal_session_token
          headers = {}
          headers['security-context'] = @security_context if @rp_version == '2.1.2' && @security_context

          response = make_http_request(:get, @rpt_endpoint, @resource_principal_token_path, headers)
          parsed_response = JSON.parse(response.data)
          if parsed_response['resourcePrincipalToken'].nil? || parsed_response['servicePrincipalSessionToken'].nil?
            raise 'Failed to get Resource Principal Token or Service Principal Session Token'
          end

          [parsed_response['resourcePrincipalToken'], parsed_response['servicePrincipalSessionToken']]
        end

        def resource_principal_session_token
          public_key = @session_key_supplier.key_pair[:public_key]
          sanitized_key = sanitize_public_key(public_key)

          body = {
            resourcePrincipalToken: @rpt,
            servicePrincipalSessionToken: @spst,
            sessionPublicKey: sanitized_key
          }

          headers = {
            :"content-type" => 'application/json',
            'content-length' => body.to_json.bytesize.to_s
          }

          response = make_http_request(:post, @rpst_endpoint, '/v1/resourcePrincipalSessionToken', headers, body)
          JSON.parse(response.data)['token']
        end

        def make_http_request(method, endpoint, path, headers = {}, body = nil)
          OCI::Retry.make_retrying_call(@retry_strategy) do
            @api_client.call_api(
              method,
              path,
              endpoint,
              operation_signing_strategy: OCI::BaseSigner::STANDARD,
              return_type: 'Stream',
              header_params: headers,
              body: @api_client.object_to_http_body(body)
            )
          end
        end

        def build_rpt_path_for_rpv212(path_template, resource_id)
          return "/20180711/resourcePrincipalTokenV212/#{resource_id}" unless path_template

          if path_template.include?('{}')
            path_template.gsub('{}', resource_id)
          else
            path_template.end_with?('/') ? "#{path_template}#{resource_id}" : "#{path_template}/#{resource_id}"
          end
        end

        def initialize_and_return_region(region_raw)
          return @region if defined?(@region)

          if region_raw && OCI::Regions::REGION_SHORT_NAMES_TO_LONG_NAMES.key?(region_raw.to_sym)
            OCI::Regions::REGION_SHORT_NAMES_TO_LONG_NAMES[region_raw.to_sym]
          else
            region_raw
          end
        end

        def reset_signers
          @key_id = "ST$#{@security_token.security_token}"
          @private_key_content = @session_key_supplier.key_pair[:private_key]
        end

        def sanitize_public_key(public_key)
          public_key.to_pem
                    .gsub(/-----BEGIN PUBLIC KEY-----/, '')
                    .gsub(/-----END PUBLIC KEY-----/, '')
                    .delete("\n")
                    .strip
        end
      end
      # rubocop:enable Metrics/ClassLength, Metrics/AbcSize, Metrics/LineLength, Metrics/CyclomaticComplexity, Metrics/ParameterLists
    end

    # FixedSessionKeySupplier holds a fixed session key that never updates
    class FixedSessionKeySupplier
      def initialize(private_key: nil)
        @private_key = private_key
        @public_key = @private_key.public_key
      end

      def key_pair
        { 'private_key': @private_key, 'public_key': @public_key }
      end

      def refresh; end
    end

    # FileBasedSessionKeySupplier holds a private key that's loaded (and potentially refreshed) from a file source.
    class FileSessionKeySupplier
      def initialize(private_key_file: nil, passphrase_file: nil)
        @private_key_file = private_key_file
        @passphrase_file = passphrase_file
        @private_key = nil
        @public_key = nil
        @refresh_lock = Mutex.new
        refresh
      end

      def key_pair
        { 'private_key': @private_key, 'public_key': @public_key }
      end

      def refresh
        @refresh_lock.lock
        pass_phrase = nil
        unless @passphrase_file.nil?
          pass_phrase = File.read(@passphrase_file) if File.exist?(@passphrase_file)
        end
        unless @private_key_file.nil?
          @private_key = OCI::Auth::Util.load_private_key_from_file(File.expand_path(@private_key_file), pass_phrase)
          @public_key = @private_key.public_key
        end
      ensure
        @refresh_lock.unlock if @refresh_lock.locked? && @refresh_lock.owned?
      end
    end
  end
end
