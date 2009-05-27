module CnsDb
  module SimpleDb
    module Errors
      class Error < RuntimeError ; end
      class RetryError < Error ; end
      class RequestError < Error
        attr_reader :request_id

        def initialize(message, request_id=nil)
          super(message)
          @request_id = request_id
        end
      end
      class InvalidDomainNameError < RequestError ; end
      class InvalidParameterValueError < RequestError ; end
      class InvalidNextTokenError < RequestError ; end
      class InvalidNumberPredicatesError < RequestError ; end
      class InvalidNumberValueTestsError < RequestError ; end
      class InvalidQueryExpressionError < RequestError ; end
      class MissingParameterError < RequestError ; end
      class NoSuchDomainError < RequestError ; end
      class NumberDomainsExceededError < RequestError ; end
      class NumberDomainAttributesExceededError < RequestError ; end
      class NumberDomainBytesExceededError < RequestError ; end
      class NumberItemAttributesExceededError < RequestError ; end
      class RequestTimeoutError < RequestError ; end
      class FeatureDeprecatedError < RequestError ; end
      class ConnectionError < Error; end
    end
    
    class DbSignal < CnsBase::RequestResponse::RequestSignal
      attr_accessor :db
      
      def initialize publisher_or_uuid, db, name=nil, params=nil
        super(publisher_or_uuid, name, params)
        
        raise if db.blank?
        
        @db = db
      end
    end
    
    class DomainSignal < DbSignal
      attr_accessor :domain
      
      def initialize publisher_or_uuid, db, domain, name=nil, params=nil
        super(publisher_or_uuid, db, name, params)
        
        raise if domain.blank?

        @domain = domain
      end
    end
    
    class ItemSignal < DomainSignal
      attr_accessor :item
      
      def initialize publisher_or_uuid, db, domain, item, name=nil, params=nil
        super(publisher_or_uuid, db, domain, name, params)
        
        raise if item.blank?

        @item = item
      end
    end

    # first level (access)
    class AddAccessSignal < DbSignal
      attr_accessor :access_key_id
      attr_accessor :secret_access_key
      attr_accessor :base_url
      attr_accessor :mode
      
      def initialize publisher_or_uuid, mode, db, access_key_id, secret_access_key, base_url="http://sdb.amazonaws.com", name=nil, params=nil
        super(publisher_or_uuid, db, name, params)
        
        raise if access_key_id.blank? || secret_access_key.blank? || base_url.blank?
        mode ||= :cached
        
        @access_key_id = access_key_id
        @secret_access_key = secret_access_key
        @base_url = base_url
        @mode = mode
      end
    end
    
    # second level (domains), belongs to access
    class CreateDomainSignal < DomainSignal; end
    
    class DeleteDomainSignal < DomainSignal; end

    class ListDomainsSignal < DbSignal
      attr_accessor :max
      attr_accessor :token
      
      def initialize publisher_or_uuid, db, max=nil, token=nil, name=nil, params=nil
        super(publisher_or_uuid, db, name, params)
      
        @max = max
        @token = token
      end
    end
    
    # third level (items), belongs to domain
    class GetAttributeSignal < ItemSignal; end

    class PutAttributeSignal < ItemSignal
      attr_accessor :attributes
      attr_accessor :replace
      
      def initialize publisher_or_uuid, db, domain, item, attributes, replace = true, name=nil, params=nil
        super(publisher_or_uuid, db, domain, item, name, params)
      
        @attributes = attributes
        @replace = replace
      end
    end
    
    class DeleteAttributeSignal < ItemSignal; end
    
    # SimpleDB queries:
    # [attr comp val and/or ...] op [...] op ...
    # attr: attribute name
    # comperative operator: = != > >= < <= starts-with
    # val: value
    # set operators: intersection, union and not (not has highest priority)
    # except not all operators are evaluated from left to right
    class QuerySignal < DomainSignal
      attr_accessor :query
      attr_accessor :max
      attr_accessor :token

      def initialize publisher_or_uuid, db, domain, query, max = nil, token = nil, name=nil, params=nil
        super(publisher_or_uuid, db, domain, name, params)
      
        @query = query
        @max = max
        @token = token
      end
    end
    
    class Database
      attr_accessor :publisher
      attr_accessor :name
      attr_accessor :access_key_id
      attr_accessor :secret_access_key
      attr_accessor :base_url
      attr_accessor :domains
      attr_accessor :mode

      def initialize publisher, name, access_key_id, secret_access_key, base_url, mode
        mode ||= :cached

        raise "unknown mode #{mode.inspect} expected: :cached, :nocache, :mem" unless [:cached, :nocache, :mem].include?(mode)
        
        @publisher = publisher
        @name = name
        @access_key_id = access_key_id
        @secret_access_key = secret_access_key
        @base_url = base_url
        @domains = {}
        @mode = mode
        
        list
      end
      
      def [] domain_name
        raise "Database not yet confirmed" unless @domains
        
        @domains[domain_name] ||= Domain.new(self, domain_name)
      end
      
      def list max=nil, token=nil
        if @mode == :mem || (@mode == :cached && max.blank? && token.blank?)
          {:domains => @domains.keys}
        else
          params = { 'Action' => 'ListDomains' }
          params['NextToken'] = token unless token.nil? || token.empty?
          params['MaxNumberOfDomains'] = max.to_s unless max.nil? || max.to_i == 0
        
          defer [@name, :on_list], :get, params
          
          nil
        end
      end
      
      def on_list doc
        results = []

        REXML::XPath.each(doc, '//DomainName/text()'){|domain|results << domain.to_s}

        token = REXML::XPath.first(doc, '//NextToken/text()').to_s
        
        @domains = {}
        
        this = self
        
        results.each{|domain_name|this[domain_name]}
        
        {:domains => @domains.keys, :token => token}
      end
      
      def defer who, method, params
        #CnsBase.logger.fatal "DO: who(#{who.inspect}) method(#{method}) params(#{params.inspect})"
        
        raise if @mode == :mem
        
        publisher.defer who, base_url, @secret_access_key, method, params.merge!('AWSAccessKeyId' => @access_key_id)
      end
    end
    
    class Domain
      attr_accessor :database
      attr_accessor :name
      attr_accessor :items
      attr_accessor :prefix

      def initialize database, name
        raise "domain name needs to be between 3 and 100 characters" if name.blank? || name.size < 3 || name.size > 100
        
        @database = database
        @name = name
        @items = {}
        @prefix = "#{@database.name}_#{@name}"
      end
      
      def [] item
        @items[item] ||= Item.new(self, item)
      end
      
      def delete
        if @database.mode == :mem
          on_delete nil
        else
          defer [@database.name, @name, :on_delete], :delete, 'Action' => 'DeleteDomain', 'DomainName' => @name
        end
        
        nil
      end
      
      def on_delete doc
        @database.domains.delete @name
        
        nil
      end
      
      def query query, max=nil, token=nil
        return {:items => @items.keys, :token => nil} if @database.mode == :mem
        
        if query.is_a?(Array)
          cond = query.shift
          
          while query.size > 0
            cond["?"] = "'#{Item.ruby_to_sdb(query.shift, self.prefix)}'"
          end
          
          query = cond
        end
        
        params = {
          'Action' => 'Query',
          'QueryExpression' => query,
          'DomainName' => @name
        }
        
        params['NextToken'] = token unless token.nil? || token.empty?
        params['MaxNumberOfItems'] = max.to_s unless max.nil? || max.to_i == 0
        
        defer [@database.name, @name, :on_query], :get, params

        nil
      end
      
      def on_query doc
        items = []
        
        REXML::XPath.each(doc, '//ItemName/text()'){|item|items << item.to_s}
        
        token = REXML::XPath.first(doc, '//NextToken/text()').to_s

        {:items => items, :token => token}
      end
      
      def create
        if @database.mode == :mem
          nil
        else
          defer [@database.name, @name, :on_create], :post, 'Action' => 'CreateDomain', 'DomainName'=> @name
        end
      end

      def on_create doc
        CnsBase.logger.info("created domain <#{name}> in db <#{database.name}>")
        
        nil
      end
      
      def defer who, method, params
        database.defer who, method, params
      end
    end

    class Item
      attr_accessor :domain
      attr_accessor :item
      attr_accessor :updated_at
      attr_accessor :attributes

      def initialize domain, item
        @domain = domain
        @item = item
        @updated_at = nil
        @attributes = {}
      end
      
      def get
        if @domain.database.mode == :mem
          @attributes
        elsif @domain.database.mode == :cached && !(@updated_at.blank? || (Time.now > @updated_at + 3600))
          @attributes
        else
          defer [domain.database.name, domain.name, @item, :on_get], :get, 'Action' => 'GetAttributes', 'DomainName' => @domain.name, 'ItemName' => @item
          nil
        end
      end
      
      def on_get doc
        attrs = {}
        
        REXML::XPath.each(doc, "//Attribute") do |attr|
          key = REXML::XPath.first(attr, './Name/text()').to_s
          value = REXML::XPath.first(attr, './Value/text()').to_s
          
          ( attrs[key] ||= [] ) << value
        end
        
        @updated_at = Time.now
        
        @attributes = simple_db_to_attributes attrs
      end
      
      def delete
        if @domain.database.mode == :mem
          on_delete nil
        else
          defer [domain.database.name, domain.name, @item, :on_delete], :delete, {'Action' => 'DeleteAttributes', 'DomainName' => @domain.name, 'ItemName' => @item}
          nil
        end
      end
      
      def on_delete doc
        @domain.items.delete @item
        nil
      end
      
      # TODO: {"" => ["", ""], "" => ["", ""]}
      def put attributes, replace=true
        attrs = attributes_to_simple_db(attributes)
        
#          @attributes.merge!(simple_db_to_attributes(attrs))
#          @updated_at = Time.now

        if @domain.database.mode == :mem
          nil
        else
          params = {
            'Action' => 'PutAttributes',
            'DomainName' => @domain.name,
            'ItemName' => @item
          }
        
          count = 0
        
          attrs.each do | key, values |
            values.each do |value|
              params["Attribute.#{count}.Name"] = key
              params["Attribute.#{count}.Value"] = value
              params["Attribute.#{count}.Replace"] = replace
              count += 1
            end
          end
        
          defer [domain.database.name, domain.name, @item, :on_put], :put, params
        end
      end
      
      def on_put doc
        nil
      end
      
      def defer who, method, params
        domain.defer who, method, params
      end
      
      def attributes_to_simple_db attributes
        attrs = {}
        
        attributes.each do | key, values |
          key = key.to_s

          raise "attribute value arrays have a limit of 256 values" if values.size > 256
          raise "attributes must be represented in an Array" unless values.is_a?(Array)
          raise "key must be between 1 and 1024 characters" if key.size < 1 || key.size > 1024
          
#            val = ([]<<values).flatten.collect do |value|

          attrs[key] = values.collect{|value|Item.ruby_to_sdb(value, domain.prefix)}
        end
        
        attrs
      end
      
      def simple_db_to_attributes simple_db_attributes
        attrs = {}
        
        simple_db_attributes.each do |key, values|
          key = key.to_s
          raise if key.size > 1024
          key = key.to_sym
          attrs[key] = values.collect{|value|Item.sdb_to_ruby(value, domain.prefix)}
        end
        
        attrs
      end
      
      BIG_VALUE = 20000000000000000000
      
      def self.ruby_to_sdb value, prefix=nil
        val = if value.is_a?(String)
          "T" + value
        elsif value.is_a?(Symbol)
          "S" + value.to_s
        elsif value.is_a?(TrueClass)
          "btrue"
        elsif value.is_a?(FalseClass)
          "bfalse"
        elsif value.is_a?(NilClass)
          # TODO: find way to search nil
          #""
          "Y" + value.to_yaml
        elsif value.is_a?(BigData)
          "B" + value.uuid
        elsif value.is_a?(Time)
          "t" + value.iso8601
        elsif value.is_a?(Integer)
          raise if value > BIG_VALUE || (value*-1) > BIG_VALUE
          
          val = value + BIG_VALUE
          
          "I" + val.to_s
        else
          "Y" + value.to_yaml
        end
        
        if val.size > 1024
          # special behaviour for big values
          bd = BigData.new prefix
          bd.set val
          val = "V" + bd.uuid.to_s
        end
        
        val
      end
      
      def self.sdb_to_ruby value, prefix=nil
        value = CGI.unescapeHTML value
        
        type = value[0,1]
        val = value[1,10000]
        
        if type == "T"
          val
        elsif type == "S"
          val.to_sym
        elsif type == "I"
          val.to_i - BIG_VALUE
        elsif type == "t"
          Time.parse(val)
        elsif type == "B"
          BigData.new prefix, val
        elsif type == "V"
          sdb_to_ruby(BigData.new(prefix, val).get)
        elsif type == "b"
          val == "true" ? true : false
        elsif type == ""
          nil
        elsif type == "Y"
          YAML.load(val)
        else
          raise "unknown value type for #{value}"
        end
      end
    end
    
    class BigData
      attr_accessor :uuid
      attr_accessor :prefix
      
      def initialize prefix, uuid=nil
        raise "prefix can not be blank" if prefix.blank?
        @prefix = prefix
        @uuid = (uuid || CnsBase.uuid).to_sym
      end
      
      def get
        file_name = self.file_name
        raise "file does not exist" unless File.exists?(file_name)
        
        YAML.load(File.read(file_name).gunzip)
      end
      
      def set data
        file_name = self.file_name
        
        if File.exists?(file_name)
          File.delete file_name
        end
        
        file = File.open(file_name, "w")
        file.write data.to_yaml.gzip
        file.close
        nil
      end
      
      def file_name
        Dir.mkdir("big_data") unless File.exists?("big_data")
        "big_data/#{prefix}_#{uuid}.yaml.gz"
      end
    end
    
    class SimpleDbCore < CnsBase::Cluster::ClusterCore
      attr_accessor :databases
      
      def initialize publisher
        super
        
        @databases = {}
      end
      
      def dispatch signal
        if signal.is_a?(CnsBase::Cluster::ClusterCreationSignal)
          if signal.deferred_response? && signal.raise_on_deferred_error!
            CnsBase.logger.info "Simple DB initialized"
          else
            if signal[:db]
              CnsBase.logger.info "Simple DB initializing"
              
              signal.defer!(publisher, AddAccessSignal.new(publisher, signal[:mode], signal[:db], signal[:access_key_id], signal[:secret_access_key], signal[:base_url]))
            end
          end
        elsif signal.is_a?(DbSignal)
          @request = signal
          @deferred = false
          
          result = if signal.deferred_response? && signal.raise_on_deferred_error!
            res = nil
            
            signal.deferrers.each do |hash|
              next if hash[:processed]
              hash[:processed] = true
              
              doc = nil
              
              begin
                doc = get_doc hash[:request], hash[:response]
              rescue CnsDb::SimpleDb::Errors::RetryError
                CnsBase.logger.fatal "RETRY DB REQUEST #{signal.uuid}"
                @request = nil
                return true
              end
              
              who = hash[:request].params[:who]
              
              res = if who.size == 2
                @databases[who[0]].send(who[1], doc)
              elsif who.size == 3
                @databases[who[0]][who[1]].send(who[2], doc)
              elsif who.size == 4
                @databases[who[0]][who[1]][who[2]].send(who[3], doc)
              else
                raise
              end
            end
            
            raise "response handles are not allowed to defer" if signal.deferred?
            
            res
          elsif signal.is_a?(AddAccessSignal)
            db_name = signal.db
            
            raise "Database exists already" if databases.include?(db_name) || databases.values.find{|db|db.access_key_id == signal.access_key_id}
            
            CnsBase.logger.info("Add SimpleDb database <#{db_name}> at #{signal.base_url} in #{signal.mode} mode") if CnsBase.logger.info?

            @databases[db_name] = Database.new self, db_name, signal.access_key_id, signal.secret_access_key, signal.base_url, signal.mode
            
            nil
          elsif signal.is_a?(CreateDomainSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain].create
          elsif signal.is_a?(DeleteDomainSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain].delete
          elsif signal.is_a?(ListDomainsSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db].list signal.max, signal.token
          elsif signal.is_a?(QuerySignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain].query signal.query, signal.max, signal.token
          elsif signal.is_a?(GetAttributeSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain][signal.item].get
          elsif signal.is_a?(PutAttributeSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain][signal.item].put signal.attributes, signal.replace
          elsif signal.is_a?(DeleteAttributeSignal)
            raise "Unknown database <#{signal.db}>" if @databases[signal.db].blank?

            @databases[signal.db][signal.domain][signal.item].delete
          else
            raise "Unknown Signal"
          end
          
          unless signal.deferred?
            hash = {:result => result, :db => signal.db}
            hash[:action] = :add_access if signal.is_a?(AddAccessSignal)
            hash[:action] = :create_domain if signal.is_a?(CreateDomainSignal)
            hash[:action] = :delete_domain if signal.is_a?(DeleteDomainSignal)
            hash[:action] = :list_domains if signal.is_a?(ListDomainsSignal)
            hash[:action] = :query if signal.is_a?(QuerySignal)
            hash[:action] = :get if signal.is_a?(GetAttributeSignal)
            hash[:action] = :put if signal.is_a?(PutAttributeSignal)
            hash[:action] = :put if signal.is_a?(PutAttributeSignal)
            hash[:action] = :put if signal.is_a?(DeleteAttributeSignal)
            hash[:domain] = signal.domain if signal.is_a?(DomainSignal)
            hash[:item] = signal.item if signal.is_a?(ItemSignal)
            signal.response = CnsBase::RequestResponse::ResponseSignal.new(:response, hash)
          end
          
          @request = nil

          return true
        end
        
        return false
      end
      
      def defer who, url, secret_access_key, method, params
        raise unless @request
        raise if @deferred
        
        @deferred = true
        
        query = nil
        
        if true # signature_version == 1
          params.merge!( {
              'Version' => '2007-11-07',
              'SignatureVersion' => '1',
              'Timestamp' => Time.now.gmtime.iso8601
            }
          )
        
          data = ''
          query = []
        
          params.keys.sort_by { |k| k.upcase }.each do |key|
            data << "#{key}#{params[key].to_s}"
            query << [key, params[key]]  # "#{key}=#{CGI::escape(params[key].to_s)}"
          end
        
          digest = OpenSSL::Digest::Digest.new('sha1')
          hmac = OpenSSL::HMAC.digest(digest, secret_access_key, data)
          signature = Base64.encode64(hmac).strip
          query << ["Signature", signature] # =#{CGI::escape(signature)}"
        else
          raise "not functioning yet"
=begin            
          params.merge!( {
              'Version' => '2007-11-07',
              'SignatureVersion' => '2',
              'SignatureMethod' => 'HmacSHA256',
              'Timestamp' => Time.now.gmtime.iso8601
            }
          )
          
          query = []
          
          query = params.keys.sort.collect do |key|
            tmp = "#{CGI::escape(key.to_s)}=#{CGI::escape(params[key].to_s)}"
            tmp.gsub('+', '%20')
          end.join("&")
          
          data = "#{method.to_s.upcase}
          sdb.amazonaws.com
          /
          #{query}"
          
          hmac = HMAC::SHA256.new(secret_access_key).update(data).digest
          signature = Base64.encode64(hmac).chomp
          
          query += "&Signature=#{signature}"
          
          CnsBase.logger.fatal query
=end
        end
        
        sig = CnsBase::HttpClient::HttpRequestSignal.new(
          publisher, 
          :get, 
          url,
          query,
          nil,
          {},
          nil,
          {:who => who, :retry => 0}
        )
        
        @request.defer!(publisher, sig)
      end

      private
      
      # this is called in case of an 503 error
      def retry! request
        return if request[:retry] > 40

        @request.defer!(publisher, CnsBase::HttpClient::HttpRequestSignal.new(publisher, request.method, request.uri, request.query, request.body, request.header, request.name, request.params.merge!({:retry => request[:retry]+1})))
        raise CnsDb::SimpleDb::Errors::RetryError.new
      end
      
      def get_doc request, response
        content = response.content
        status = response.status
        
        retry!(request) if status == 503
        
#          CnsBase.logger.fatal("#{response.status}\n#{response.content}") if CnsBase.logger.fatal?
        
        raise(CnsDb::SimpleDb::Errors::ConnectionError.new("status: #{status}")) unless (200..400).include?(status.to_i)
        
        doc = REXML::Document.new(content)
        error = doc.get_elements('*/Errors/Error')[0]
        
        unless error.nil?
          error_class = Module.class_eval("CnsDb::SimpleDb::Errors::#{error.get_elements('Code')[0].text}Error")
          message = error.get_elements('Message')[0].text
          id = doc.get_elements('*/RequestID')[0].text
          
          raise error_class.new(message,id)
        end
        
        doc
      end
    end
  end
end
