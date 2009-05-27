require 'rubygems'
require 'cns_base'

require 'logger'
require 'time'
require 'cgi'
require 'uri'
require 'net/http'
require 'base64'
require 'openssl'
require 'rexml/document'
require 'rexml/xpath'
require 'hmac-sha2'

#require 'ruby-debug'

module CnsDb
  VERSION = '0.0.1'
end

$:.unshift(File.dirname(__FILE__)) unless
  $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

require 'cns_db/simpledb'
require 'cns_db/simpledbdao'
