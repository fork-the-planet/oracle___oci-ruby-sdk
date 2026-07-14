# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

require 'net/http'
require 'openssl'
require 'securerandom'
require 'uri'
require 'circuitbox'

module OCI
  module Auth
    # A certificate retriever which reads PEM-format strings from URLs.
    class UrlBasedCertificateRetriever
      # Creates a new UrlBasedCertificateRetriever
      #
      # @param [String] certificate_url The URL from which to retrieve a certificate. It is assumed that what we retrieve is the PEM-formatted string for the certificate
      # @param [String] private_key_url The URL from which to retrieve the private key corresponding to certificate_url (if any). It is assumed that what we retrieve is the PEM-formatted string for
      # @param [String] private_key_passphrase The passphrase of the private key (if any)
      def initialize(certificate_url, private_key_url: nil, private_key_passphrase: nil)
        raise 'A certificate_url must be supplied' unless certificate_url

        @certificate_url = certificate_url
        @private_key_url = private_key_url
        @private_key_passphrase = private_key_passphrase

        @certificate_pem = nil
        @private_key_pem = nil
        @private_key = nil

        @refresh_lock = Mutex.new

        uri = URI(certificate_url)
        @certificate_retrieve_http_client = Net::HTTP.new(uri.hostname, uri.port)

        if !@private_key_url.nil? && !@private_key_url.strip.empty?
          uri = URI(private_key_url.strip)
          @private_key_retrieve_http_client = Net::HTTP.new(uri.hostname, uri.port)
        else
          @private_key_retrieve_http_client = nil
        end

        refresh
      end

      # @return [String] The certificate as a PEM formatted string
      def certificate_pem
        @refresh_lock.lock
        pem = @certificate_pem
        @refresh_lock.unlock

        pem
      end

      # @return [OpenSSL::X509::Certificate] The certificate as an {OpenSSL::X509::Certificate}. This converts the
      # PEM-formatted string into a {OpenSSL::X509::Certificate}
      def certificate
        cert_pem = certificate_pem
        OpenSSL::X509::Certificate.new(cert_pem)
      end

      # @return [String] The private key as a PEM-formatted string
      def private_key_pem
        @refresh_lock.lock
        pem = @private_key_pem
        @refresh_lock.unlock

        pem
      end

      # @return [OpenSSL::PKey::RSA] The private key
      def private_key
        @refresh_lock.lock
        key = @private_key
        @refresh_lock.unlock

        key
      end

      # rubocop:disable Metrics/CyclomaticComplexity
      def refresh
        @refresh_lock.lock
        OCI::Retry.make_retrying_call(OCI::Auth::Util.default_imds_retry_policy, call_name: 'x509') do
          OCI::Auth::Util.circuit.run do
            response = request_metadata(@certificate_url)
            raise OCI::Errors::NetworkError.new(response.body, response.code) unless response.is_a?(Net::HTTPSuccess)

            @certificate_pem = response.body
          end
        end

        if @private_key_retrieve_http_client
          OCI::Retry.make_retrying_call(OCI::Auth::Util.default_imds_retry_policy, call_name: 'x509') do
            OCI::Auth::Util.circuit.run do
              response = request_metadata(@private_key_url)
              raise OCI::Errors::NetworkError.new(response.body, response.code) unless response.is_a?(Net::HTTPSuccess)

              @private_key_pem = response.body
              @private_key = OpenSSL::PKey::RSA.new(@private_key_pem, @private_key_passphrase || SecureRandom.uuid)
            end
          end
        end
      ensure
        @refresh_lock.unlock if @refresh_lock.locked? && @refresh_lock.owned?
      end

      # rubocop:enable Metrics/CyclomaticComplexity

      def request_metadata(url)
        uri = URI(url)
        Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
          response = http.request(OCI::Auth::Util.get_metadata_request(url, 'get'))
          return response
        end
      rescue StandardError => e
        pp "Request to #{url} failed: #{e.class} - #{e.message}"
        raise
      end
    end
  end
end
