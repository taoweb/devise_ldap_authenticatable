require 'net/ldap'

module Devise

  # simple adapter for ldap credential checking
  # ::Devise.ldap_host
  module LdapAdapter
    def self.valid_credentials?(login, attributes, password)
      login = "#{login}@#{::Devise.ldap_base_dn.gsub(/(.+,dc=)/, '')}"
      @encryption = ::Devise.ldap_ssl ? :simple_tls : nil
      ldap = Net::LDAP.new(:encryption => @encryption, :base => ::Devise.ldap_base_dn)
      ldap.host = ::Devise.ldap_host
      ldap.port = ::Devise.ldap_port
      ldap.auth login, password
      ldap.bind ? true : false
    end
  end
end
