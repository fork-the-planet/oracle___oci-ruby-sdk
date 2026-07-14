# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

require 'oci/base_signer'

module OCI
  module Auth
    module Signers
      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      # A requests signer that is intended to be used when signing requests for RPv2.1 using a key pair
      class KeyPairSigner < OCI::BaseSigner
        # Creates a new KeyPairSigner
        #
        # @param [String] rp_version
        # @param [String] resource_id
        # @param [String] tenancy_id
        # @param [OpenSSL::PKey::RSA] private_key The private key whose corresponding public key was provided when requesting the token
        # @param [Array<String>] headers_to_sign_in_all_requests An array of headers which will be signed in each request. If not provided, defaults to {OCI::BaseSigner::GENERIC_HEADERS}
        # @param [Array<String>] body_headers_to_sign An array of headers which should be signed on requests with bodies. If not provided, defaults to {OCI::BaseSigner::BODY_HEADERS}
        def initialize(
          rp_version,
          resource_id,
          tenancy_id,
          private_key,
          headers_to_sign_in_all_requests: OCI::BaseSigner::GENERIC_HEADERS,
          body_headers_to_sign: OCI::BaseSigner::BODY_HEADERS
        )
          if %w[2.1.1 2.1.2].include?(rp_version) && tenancy_id && resource_id
            @api_key = "resource/v#{rp_version}/#{tenancy_id}/#{resource_id}"
          elsif rp_version == '2.1' && resource_id
            @api_key = "resource/v2.1/#{resource_id}"
          else
            raise ArgumentError, 'Resource Id or Tenancy Id or OCI_RESOURCE_PRINCIPAL_VERSION is missing'
          end

          raise ArgumentError, 'Private Key is missing' if private_key.nil?

          @private_key = private_key

          @headers_to_sign_in_all_requests = headers_to_sign_in_all_requests
          @body_headers_to_sign = body_headers_to_sign

          super(
            @api_key,
            @private_key,
            headers_to_sign_in_all_requests: headers_to_sign_in_all_requests,
            body_headers_to_sign: body_headers_to_sign
          )
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    end
  end
end
