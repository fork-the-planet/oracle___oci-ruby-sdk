# Copyright (c) 2016, 2026, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

require 'openssl'
require 'securerandom'
require 'circuitbox'

module OCI
  module Auth
    # Contains utility methods to support functionality in the {OCI::Auth} module, for example being able
    # to extract information from certificates and scrubbing certificate information for calls to Auth Service
    module Util
      AUTHORIZATION_HEADER = 'Authorization'.freeze
      AUTHORIZATION_HEADER_VALUE = 'Bearer Oracle'.freeze

      def self.get_tenancy_id_from_certificate(x509_certificate)
        subject_array = x509_certificate.subject.to_a
        subject_array.each do |subject_name|
          # subject_name is actually a triple like:
          #   ["OU", "<name>", "<number>"]
          if subject_name[0] == 'OU' && subject_name[1].include?('opc-tenant:')
            # 'opc-tenant:' is 11 character long, so we want to start at the index after that and to the end of the string (-1)
            return subject_name[1][11..-1]
          end
        end

        raise 'Certificate did not contain a tenancy in its subject'
      end

      def self.colon_separate_fingerprint(raw_fingerprint)
        raw_fingerprint.gsub(/(.{2})(?=.)/, '\1:\2')
      end

      def self.sanitize_certificate_string(cert_string)
        cert_string.gsub('-----BEGIN CERTIFICATE-----', '')
                   .gsub('-----END CERTIFICATE-----', '')
                   .gsub('-----BEGIN PUBLIC KEY-----', '')
                   .gsub('-----END PUBLIC KEY-----', '')
                   .delete("\n")
      end

      def self.get_metadata_request(request_url, type)
        uri = URI(request_url)
        case type
        when 'post'
          request = Net::HTTP::Post.new(uri)
        when 'get'
          request = Net::HTTP::Get.new(uri)
        when 'put'
          request = Net::HTTP::Put.new(uri)
        else
          raise "Unknown request-type #{type} provided."
        end
        request[AUTHORIZATION_HEADER] = AUTHORIZATION_HEADER_VALUE
        request
      end

      def self.load_private_key_from_file(private_key_file, passphrase)
        private_key_data = File.read(File.expand_path(private_key_file)).to_s.strip
        load_private_key(private_key_data, passphrase)
      end

      def self.load_private_key(private_key_date, passphrase)
        OpenSSL::PKey::RSA.new(
          private_key_date,
          passphrase || SecureRandom.uuid
        )
      end

      def self.default_imds_retry_policy
        retry_strategy_map = {
          OCI::Retry::Functions::ShouldRetryOnError::ErrorCodeTuple.new(404, 'NotFound') => true,
          OCI::Retry::Functions::ShouldRetryOnError::ErrorCodeTuple.new(409, 'IncorrectState') => true,
          OCI::Retry::Functions::ShouldRetryOnError::ErrorCodeTuple.new(429, 'TooManyRequests') => true,
          OCI::Retry::Functions::ShouldRetryOnError::ErrorCodeTuple.new(501, 'MethodNotImplemented') => false
        }
        OCI::Retry::RetryConfig.new(
          base_sleep_time_millis: 1000,
          exponential_growth_factor: 2,
          should_retry_exception_proc:
            OCI::Retry::Functions::ShouldRetryOnError.retry_strategy_with_customized_retry_mapping_proc(retry_strategy_map),
          sleep_calc_millis_proc: OCI::Retry::Functions::Sleep.exponential_backoff_with_full_jitter,
          max_attempts: 7,
          max_elapsed_time_millis: 180_000, # 3 minutes
          max_sleep_between_attempts_millis: 30_000
        )
      end

      def self.circuit
        Circuitbox.circuit(:imds_metadata, exceptions: [OCI::Errors::NetworkError, OCI::Errors::ServiceError],
                                           volume_threshold: 10,
                                           time_window: 120,
                                           error_threshold: 80,
                                           sleep_window: 120)
      end
    end
  end
end
