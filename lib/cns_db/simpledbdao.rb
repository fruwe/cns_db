module CnsDb
  # User permission based - Data access object
  module SimpleDbDao
    # SimpleDbDao stores ruby hash based data in simple db and manages the permissions to these data.
    #
    # client data format:
    # 
    # 1 user has one to many permission groups
    # permission groups have certain permissions to data
    # each data object will be connected to the user, who created the data or to the highest admin
    # thus all data objects and relation objects have a relation to at least one user
    # 
    # auto fields: :updated_at, :created_at, :owner
=begin      
    must be easy to find by group

    group has permissions to table, field, page, rwc, owner

    versioning....

    hash = 
    {
      :users =>
      {
        "users_1" =>
        {
          :login => "pete",
          :password => "1234"
        }
      },
      :groups =>
      {
        "groups_1" =>
        {
          :parent => nil,
          :access_key =>　"pete",
          :password => "1234",
          :name => "admins",
          :union => ["group_2"]
        }
      },
      :permissions =>
      {
        "permissions_1" =>
        {
          :data => "",
          :group => "1"
        }
      },
      :relations =>
      {
        "relations_1" => 
        {
          :from => ["geos_1"],
          :to => ["medias_1"],
          :between => []
        }
      },h
      :data => 
      {
        :geos =>
        {
          "geos_1" => {
            :name => ["USA"],
            :medias => Relation.to(:data, :medias)
          }
        },
        :medias => 
        {
          "medias_1" =>
          {
            :data => [...], # 100KB example jpg
            :name => "hello.jpg"
          }
        }
      }
    }
=end      
  end

  # Easy Access to Simple Db
  module SimpleDbDao
    # Access abstraction layer
    #
    # Features:
    #  - access to simpledb via hash map
    #  - automatic created_at updated_at
    #  - automatic relations
    #  - automatic handling of big files
    #  - save data not in domains per table (thus allowing more than simpledb limit)
    #  - automatic id
    #  - easy querying
    #
    # Usage:
    #
    # h = SimpleDbHash.new
    #
    # Creation: h[:medias] << {:name => ["Hello"], :hoho => [234, 422], :bought_at => [Time.now]}
    # Deletion: h[:medias][3].delete
    # Edit: h[:medias][3][:name] = ["Butzke"]
    # Edit: h[:medias][3] = :name => ["Butzke"], :price => [0]
    # Get: h[:medias][3] # Get whole third dataset.
    # Or the following:
    # h[:medias][1][:name] # gets names of media id 1
    # h[:medias][:name] == "Christian"
    # h[:medias][:created_at] > Time.now
    # h[:medias][:owner] == h.row(:users, 1)
    #
    # h[:users] << {:hello => "hoho"}
    # h[:venue] << {:cool => true}
    # send request
    # 
    # h.connect :owner, :from => h.row(:users, response[:users].first, :to => response[:venue].first)
    # send request
    # 
    # h.get h.row(:users, 1), :owner
    # send request
    # 
    # h.unconnect :owner, :from => h.row(:users, response[:users].first, :to => response[:venue].first)
    # send request
    # 
    # h.get h.row(:users, 1), :owner
    # send request
    # 
    class SimpleDbHash
      INTERNAL_COLUMN_TABLE = :INTCOLTABLE
      
      class Table
        attr_accessor :internal
        attr_accessor :table_name
        attr_accessor :new_counter

        def initialize table_name
          raise "Table name needs to be a symbol" unless table_name.is_a?(Symbol)

          @table_name = table_name
          @new_counter = -1
          @internal = {}
        end
        
        def [] field_or_id
          if field_or_id.is_a?(Integer)
            @internal[field_or_id] ||= Row.new(field_or_id)
          elsif field_or_id.is_a?(Symbol)
            @internal[field_or_id] ||= Predicat.new(field_or_id)
          else
            raise "field_or_id needs to be a symbol or id"
          end
        end

        def []= field_or_id, hash
          row = self[field_or_id]
          row.set hash
          row
        end
        
        def << hash
          row = Row.new(@new_counter)
          row.set hash
          @internal[@new_counter] = row
          @new_counter -= 1
          row
        end
        
        # get: {:action => :get, :tables => {:table_name => {1 => [:field_1]}}}
        # put: {:action => :put, :tables => {:table_name => {1 => {:field_1 => value_1}}}
        # delete: {:action => :delete, :tables => {:table_name => [1]}
        # query: {:action => :query, :tables => {:table_name => {:condition => "['#{SimpleDbHash::INTERNAL_COLUMN_TABLE}' = ?] intersection ['field_1' > ?]", :values => [:table_name, value_1]}}}
        def get
          if @internal.empty?
            condition = ["['#{SimpleDbHash::INTERNAL_COLUMN_TABLE}' = ?]"]
            vals = [@table_name]
            
            return {:action => :query, :tables => {@table_name => {:condition => "#{condition.join(" intersection ")}", :values => vals}}}
          end
          
          fields = @internal.values.find_all{|i|i.is_a?(Predicat)}
          rows = @internal.values.find_all{|i|i.is_a?(Row)}
          
          raise self.inspect if fields.size + rows.size != @internal.size
          raise "fields and rows can not be mixed" if fields.size > 0 && rows.size > 0
          
          if rows.empty?
            # For queries
            field_results = fields.collect{|f|f.get}
            actions = field_results.collect{|h|h[:action]}.uniq
            non_row_actions = actions - [:get, :query]
            raise "actions can not be mixed" if non_row_actions.size > 0

            condition = []
            vals = []
            only = []
            
            field_results.each do |h| 
              if h[:action] == :query
                condition << h[:query][:condition]
                vals += h[:query][:values]
              elsif h[:action] == :get
                only += h[:fields] 
              else
                raise "internal error"
              end
            end
            
            condition << "['#{SimpleDbHash::INTERNAL_COLUMN_TABLE}' = ?]"
            vals << @table_name
            
            {:action => :query, :tables => {@table_name => {:only => only, :condition => "#{condition.join(" intersection ")}", :values => vals}}}
          elsif fields.empty?
            row_results = rows.collect{|r|r.get}
            action = row_results.first[:action]
            
            raise "actions can not be mixed" if row_results.find{|h|h[:action] != action}
            
            # get: {:action => :get, :fields => {1 => [:field_1]}}
            # put: {:action => :put, :values => {1 => {:field_1 => value_1}}}
            # delete: {:action => :delete, :ids => [1]}
            if action == :get
              map = {}
              row_results.each{|h|map.merge! h[:fields]}
              {:action => :get, :tables => {@table_name => map}}
            elsif action == :put
              map = {}
              row_results.each{|h|map.merge! h[:values]}
              {:action => :put, :tables => {@table_name => map}}
            elsif action == :query
              raise "query not allowed for row actions"
            elsif action == :delete
              ids = []
              row_results.each{|h|ids += h[:ids]}
              {:action => :delete, :tables => {@table_name => ids}}
            else
              raise "unknown error"
            end
          else
            raise "unknown error"
          end
        end
      end
      
      class Row
        attr_accessor :predicates
        attr_accessor :id
        attr_accessor :op

        def initialize id
          raise "Id needs to be an integer" unless id.is_a?(Integer)

          @id = id
          @predicates = []
          @op = nil
        end
        
        def set hash
          raise "row needs to be set to a hash not to a #{hash.class}" unless hash.is_a?(Hash)
          
          hash.each do |key, value|
            self[key] = value
          end
        end
        
        def delete
          @op = :delete
        end
        
        def [] field
          p = Predicat.new(field)
          predicates << p
          p
        end
        
        def []= field, value
          f = self[field]
          f.set value
          f
        end
        
        # get: {:action => :get, :fields => {1 => [:field_1]}}
        # put: {:action => :put, :values => {1 => {:field_1 => value_1}}}
        # delete: {:action => :delete, :ids => [1]}
        # query: raise
        def get
          if not predicates.empty?
            preds = predicates.collect{|p|p.get}
            action = preds.first[:action]
            
            raise "actions can not be mixed" if preds.find{|h|h[:action] != action}
            
            if action == :get
              fields = []
              preds.each{|h|fields += h[:fields]}
              {:action => :get, :fields => {@id => fields}}
            elsif action == :put
              map = {}
              preds.each{|h|map.merge! h[:values]}
              {:action => :put, :values => {@id => map}}
            elsif action == :query
              raise "querys can not be performed on rows"
            else
              raise "unknown action #{action}"
            end
          elsif op == :delete
            {
              :action => :delete, :ids => [@id]
            }
          else
            {:action => :get, :fields => {@id => []}}
          end
        end
      end
      
      class Predicat
        attr_accessor :field_name
        attr_accessor :op
        attr_accessor :value

        def initialize field_name
          raise "Field name needs to be a symbol" unless field_name.is_a?(Symbol)

          @field_name = field_name
          @op = nil
          @value = nil
        end

        def set value
          raise "value needs to be an array (#{value.inspect})" unless value.is_a?(Array)
          set_op "set", value
        end
        
        def == value
          set_op "=", value
        end
        
        def > value
          set_op ">", value
        end
        
        def < value
          set_op "<", value
        end
        
        def >= value
          set_op ">=", value
        end
        
        def <= value
          set_op "<=", value
        end
        
        def not value
          set_op "!=", value
        end
        
        def starts_with value
          set_op "starts-with", value
        end
        
        def set_op operator, value
          raise unless @op.blank? || @value.blank?
          @op = operator
          @value = value
        end
        
        # get: {:action => :get, :fields => [:field_1]}
        # put: {:action => :put, :values => {:field_1 => value_1}}
        # delete: exception
        # query: {:action => :query, :query => {:condition => "'field_1' > ?", :values => [value_1]}}
        def get
          if @op.blank? && @value.blank?
            {
              :action => :get,
              :fields => [@field_name]
            }
          elsif @op == "set"
            raise "value must be an Array" unless @value.is_a?(Array)
            
            {
              :action => :put,
              :values => {@field_name => @value}
            }
          elsif @op
            values = @value.is_a?(Array) ? @value : [@value]
            {
              :action => :query,
              :query => {:condition => "[" + values.collect{|value|"'#{field_name}' #{@op} ?"}.join(" OR ") + "]", :values => values}
            }
          else
            raise "Unknown error"
          end
        end
      end

      attr_accessor :tables
      attr_accessor :connections
      
      def initialize
        @tables = []
        @connections = []
      end
      
      def [] table_name
        table = @tables.find{|table|table.table_name == table_name}
        
        unless table
          table = Table.new(table_name)
          @tables << table
        end
        
        table
      end
      
      def connect! relation, left_rows_array, right_rows_array = []
        raise "relation must be symbol" unless relation.is_a?(Symbol)

        left_tables = []
        right_tables = []
        left_rows = []
        right_rows = []
        
        left_rows_array.each do |table, id|
          raise "table name must be symbol not #{table.inspect}" unless table.is_a?(Symbol)
          raise "id name must be an integer not #{id.inspect}" unless id.is_a?(Integer)
          left_tables << table
          left_rows << SimpleDbHashAccessCore.to_item(table, id)
        end
        
        right_rows_array.each do |table, id|
          raise "table name must be symbol not #{table.inspect}" unless table.is_a?(Symbol)
          raise "id name must be an integer not #{id.inspect}" unless id.is_a?(Integer)
          right_tables << table
          right_rows << SimpleDbHashAccessCore.to_item(table, id)
        end
        
        left_tables.uniq!
        right_tables.uniq!
        left_rows.uniq!
        right_rows.uniq!
        
        raise "at least two rows are necessary for an connection" if left_rows.size + right_rows.size < 2
        
        self[:relations] << {:tables => (left_tables + right_tables).uniq, :rows => (left_rows + right_rows).uniq, :left_tables => left_tables, :left_rows => left_rows, :right_tables => right_tables, :right_rows => right_rows, :relation => [relation]}
        
        nil
      end
      
      def unconnect! ids_or_hash
        if ids_or_hash.is_a?(Integer)
          self[:relations][ids_or_hash].delete
        elsif ids_or_hash.is_a?(Array)
          ids_or_hash.each do |id|
            unconnect! id
          end
        elsif ids_or_hash.is_a?(Hash)
          raise "hash needs to contain :relations hash, not #{ids_or_hash.inspect}" unless ids_or_hash[:relations].is_a?(Hash)
          unconnect! ids_or_hash[:relations].keys
        else
          raise "invalid parameter format #{ids_or_hash.inspect}"
        end
      end
      
      def connection relation, table, id, side = :both
        raise "relation must be symbol" unless relation.is_a?(Symbol)
        raise "table name must be symbol" unless table.is_a?(Symbol)
        raise "id name must be an integer" unless id.is_a?(Integer)
        raise "side must be :both (default), :left or :right" unless [:left, :right, :both].include?(side)
        
        rows_column = (side == :both ? :rows : (side == :left ? :left_rows : :right_rows))
        
        self[:relations][:relation] == relation
        self[:relations][rows_column] == SimpleDbHashAccessCore.to_item(table, id)
      end
      
      def rows_of_connection connection_hash, side = :both, exclude_table=nil, exclude_id=nil
        raise "hash needs to contain :relations hash, not #{connection_hash.inspect}" unless connection_hash[:relations].is_a?(Hash)
        raise "excluded table name must be symbol or blank" unless exclude_table.is_a?(Symbol) || exclude_table.blank?
        raise "excluded id name must be an integer or blank" unless exclude_id.is_a?(Integer) || (exclude_table.blank? && exclude_id.blank?)
        raise "side must be :both (default), :left or :right" unless [:left, :right, :both].include?(side)
        
        rows_column = (side == :both ? :rows : (side == :left ? :left_rows : :right_rows))

        connection_hash[:relations].values.each do |hash|
          hash[rows_column].each do |item|
            table, id = SimpleDbHashAccessCore.to_row(item)
            unless exclude_table==table && exclude_id==id
              self[table][id]
            end
          end
        end
      end
      
      # get: {:action => :get, :tables => {:table_name => {:fields => {1 => [:field_1]}}}}
      # put: {:action => :put, :tables => {:table_name => {:values => {1 => {:field_1 => value_1}}}}
      # delete: {:action => :delete, :tables => {:table_name => {:ids => [1]}}
      # query: {:action => :query, :tables => {:table_name => {:condition => "['#{SimpleDbHash::INTERNAL_COLUMN_TABLE}' = ? and 'field_1' > ?]", :values => [:table_name, value_1]}}}
      def get
        raise "empty request" if @tables.empty?
          
        results = @tables.collect{|table|table.get}
      
        action = results.first[:action]
      
        raise "actions can not be mixed\n#{results.pretty_inspect}" if results.find{|h|h[:action] != action}
      
        t = {}
      
        results.each do |hash|
          begin
            t.merge! hash[:tables]
          rescue
            raise results.inspect
          end
        end
      
        {:action => action, :tables => t}
      end
    end
    
    class AddAccessSignal < CnsBase::RequestResponse::RequestSignal
      attr_accessor :simple_db_url
      attr_accessor :db
      attr_accessor :table_prefix
      
      def initialize publisher_or_uuid, simple_db_url, db, table_prefix, name=nil, params=nil
        super(publisher_or_uuid, name, params)
        
        @simple_db_url = simple_db_url
        @db = db
        @table_prefix = table_prefix
        
        raise "AddAccessSignal's parameters can not be blank" if @simple_db_url.blank? || @db.blank? || @table_prefix.blank?
      end
    end

    class SimpleDbHashRequestSignal < CnsBase::RequestResponse::RequestSignal
      attr_accessor :hash
      
      def initialize publisher_or_uuid, hash, name=nil, params=nil
        super(publisher_or_uuid, name, params)
        
        raise "hash needs to be a SimpleDbHash" unless hash.is_a?(SimpleDbHash)
        
        @hash = hash
      end
    end

    class SchemaInfoSignal < CnsBase::RequestResponse::RequestSignal
      def initialize publisher_or_uuid, name=nil, params=nil
        super(publisher_or_uuid, name, params)
      end
    end
    
    class SimpleDbHashResponseSignal < CnsBase::RequestResponse::ResponseSignal
      attr_accessor :hash
      
      def initialize hash, name=nil, params=nil
        super(name, params)
        
        @hash = hash
      end
    end
    
    class SimpleDbHashAccessCore < CnsBase::Cluster::ClusterCore
      def self.to_item table_name, id
        id = id.to_i
        "#{table_name} X #{CnsDb::SimpleDb::Item::ruby_to_sdb(id)}"
      end
      
      def self.to_row item
        table_name, id = item.split(" X ")
        id = CnsDb::SimpleDb::Item::sdb_to_ruby(id)
        [table_name.to_sym, id]
      end
      
      attr_accessor :simple_db_url
      attr_accessor :db
      attr_accessor :table_prefix
      attr_accessor :schema
      
      def initialize publisher
        super
        
        @simple_db_url = nil
        @db = nil
        @table_prefix = nil
        @schema = nil
      end
      
      def dispatch signal
        if signal.is_a?(CnsBase::Cluster::ClusterCreationSignal)
          if signal.deferred_response? && signal.raise_on_deferred_error!
            CnsBase.logger.info "Simple DB Hash Access initialized"
          else
            if signal[:simple_db_url]
              CnsBase.logger.info "Simple DB Hash Access initializing"
              signal.defer!(publisher, AddAccessSignal.new(publisher, signal[:simple_db_url], signal[:db], signal[:table_prefix]))
            end
          end
        elsif signal.is_a?(AddAccessSignal)
          if signal.deferred_response? && signal.raise_on_deferred_error!
            signal.deferrers.each do |hash|
              response = hash[:response]
              
              next if response.blank? # upon to_db deferrers will have new requests
              
              if response.params[:action] == :create_domain && response.params[:domain] == "#{@table_prefix}_schema"
                next if hash[:processed]
                hash[:processed] = true
                to_db CnsDb::SimpleDb::GetAttributeSignal.new(publisher, @db, "#{@table_prefix}_schema", "schema_info"), signal
              elsif response.params[:action] == :get && response.params[:item] == "schema_info"
                @schema ||= {}

                response.params[:result].each do |table_name, infos|
                  @schema[table_name] = infos.first
                end

                signal.response = CnsBase::RequestResponse::ResponseSignal.new
              end
            end
          else
            @simple_db_url = signal.simple_db_url
            @db = signal.db
            @table_prefix = signal.table_prefix
            
            raise if @simple_db_url.blank? || @db.blank? || @table_prefix.blank?

            to_db CnsDb::SimpleDb::CreateDomainSignal.new(publisher, @db, "#{@table_prefix}_data_1"), signal
            to_db CnsDb::SimpleDb::CreateDomainSignal.new(publisher, @db, "#{@table_prefix}_schema"), signal
          end
          
          return true
        elsif signal.is_a?(SchemaInfoSignal)
          raise "SimpleDbHashAccessCore needs to be initialized with an AddAccessSignal" if @simple_db_url.blank? || @db.blank? || @table_prefix.blank?
          
          signal.response = SimpleDbHashResponseSignal.new(@schema)
          
          return true
        elsif signal.is_a?(SimpleDbHashRequestSignal)
          raise "SimpleDbHashAccessCore needs to be initialized with an AddAccessSignal" if @simple_db_url.blank? || @db.blank? || @table_prefix.blank?

          simple_hash = signal.hash.get
          action = simple_hash[:action]
          tables = simple_hash[:tables]

          result = {}
          
          if signal.deferred_response? && signal.raise_on_deferred_error!
            # finish request
            if action == :get
              signal.deferrers.each do |h|
                attrs = h[:response].params[:result]
                item = h[:request].item
                table_name, id = SimpleDbHashAccessCore.to_row(item)
                fields = h[:request].params[:only]
                
                unless fields.empty?
                  attrs.keys.each do |key|
                    attrs.delete(key) unless fields.include?(key)
                  end
                end
                
                attrs.delete(SimpleDbHash::INTERNAL_COLUMN_TABLE)
                
                result[table_name] ||= {}
                result[table_name][id] = attrs
              end
            elsif action == :put
              signal.deferrers.each do |h|
                if h[:request].is_a?(CnsDb::SimpleDb::GetAttributeSignal)
                  next if h[:processed]
                  h[:processed] = true

                  item = h[:request].item
                  table_name, id = SimpleDbHashAccessCore.to_row(item)

                  # checked if records exists... let's see
                  attributes = h[:request].params[:set_to]
                  
                  if h[:response][:result][SimpleDbHash::INTERNAL_COLUMN_TABLE].blank?
                    # new record / deleted record
                    id = new_record table_name
                    item = SimpleDbHashAccessCore.to_item table_name, id
                  end

                  attributes[SimpleDbHash::INTERNAL_COLUMN_TABLE] = [table_name]
                  attributes[:created_at] = [Time.now]
                  attributes[:updated_at] = [Time.now]
                  
                  to_db(CnsDb::SimpleDb::PutAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, attributes, true), signal)
                elsif h[:request].is_a?(CnsDb::SimpleDb::PutAttributeSignal)
                  item = h[:request].item
                  table_name, id = SimpleDbHashAccessCore.to_row(item)
                  
#                    attrs = h[:request].attributes
#                    attrs.delete SimpleDbHash::INTERNAL_COLUMN_TABLE
                  
                  result[table_name] ||= {}
                  result[table_name][id] = :put
                end
              end
            elsif action == :delete
            elsif action == :query
              signal.deferrers.each do |h|
                next unless h[:response]
                
                if h[:request].is_a?(CnsDb::SimpleDb::QuerySignal)
                  next if h[:processed]
                  h[:processed] = true
                  
                  h[:response].params[:result][:items].each do |item|
                    to_db(CnsDb::SimpleDb::GetAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, nil, :only => h[:request].params[:only]), signal)
                  end
                elsif h[:request].is_a?(CnsDb::SimpleDb::GetAttributeSignal)
                  attrs = h[:response].params[:result]
                  table_name, id = SimpleDbHashAccessCore.to_row(h[:request].item)
                  only = h[:request].params[:only] || []
                  
                  unless only.empty?
                    attrs.keys.each do |key|
                      attrs.delete(key) unless only.include?(key)
                    end
                  end

                  attrs.delete(SimpleDbHash::INTERNAL_COLUMN_TABLE)

                  result[table_name] ||= {}
                  result[table_name][id] = attrs
                else
                  raise "internal error"
                end
              end
            else
              raise "unknown error"
            end

            signal.response = SimpleDbHashResponseSignal.new(result) unless signal.deferred?
          else
            # get: {:action => :get, :tables => {:table_name => {1 => [:field_1]}}}
            if action == :get
              tables.each do |table_name, hash|
                schema_update_table table_name
                
                hash.each do |id, fields|
                  item = SimpleDbHashAccessCore.to_item table_name, id
                  to_db(CnsDb::SimpleDb::GetAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, nil, :only => fields), signal)
                end
              end

            # put: {:action => :put, :tables => {:table_name => {1 => {:field_1 => value_1}}}
            elsif action == :put
              tables.each do |table_name, hash|
                schema_update_table table_name
                
                hash.each do |id, attributes|
                  if id < 0
                    # new record set
                    id = new_record table_name
                    item = SimpleDbHashAccessCore.to_item table_name, id
                    attributes.merge!({:updated_at => [Time.now], :created_at => [Time.now], SimpleDbHash::INTERNAL_COLUMN_TABLE => [table_name]})
                    to_db(CnsDb::SimpleDb::PutAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, attributes, true), signal)
                  else
                    # maybe old record set, get first
                    item = SimpleDbHashAccessCore.to_item table_name, id
                    attributes.delete(SimpleDbHash::INTERNAL_COLUMN_TABLE)
                    attributes.delete(:updated_at)
                    attributes.delete(:created_at)
                    to_db(CnsDb::SimpleDb::GetAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, nil, :set_to => attributes), signal)
                  end
                end
              end
            # delete: {:action => :delete, :tables => {:table_name => [1]}
            elsif action == :delete
              tables.each do |table_name, ids|
                schema_update_table table_name
                
                ids.each do |id|
                  item = SimpleDbHashAccessCore.to_item table_name, id
                  to_db(CnsDb::SimpleDb::DeleteAttributeSignal.new(publisher, @db, "#{@table_prefix}_data_1", item, nil), signal)
                end
              end
            # query: {:action => :query, :tables => {:table_name => {:condition => ["['#{SimpleDbHash::INTERNAL_COLUMN_TABLE}' = ? and 'field_1' > ?]"], :values => [:table_name, value_1]}}}
            elsif action == :query
              tables.each do |table_name, hash|
                schema_update_table table_name
                
                condition = hash[:condition]
                values = hash[:values]
                only = hash[:only]

                query = [condition] + values
                to_db(CnsDb::SimpleDb::QuerySignal.new(publisher, @db, "#{@table_prefix}_data_1", query, nil, nil, nil, :only => only), signal)
              end
            else
              raise "internal error"
            end
          end
          
          return true
        else
          return false
        end
      end
      
      def new_record table_name
        schema_update_table table_name
        
        id = @schema[table_name][:lid]
        
        @schema[table_name][:lid] += 1
        
        save_schema
        
        id
      end
      
      def schema_update_table table_name
        unless @schema[table_name]
          @schema[table_name] = {:lid => 0}
          save_schema
        end
      end
      
      def save_schema
        hash = {}
        @schema.each{|table_name, info|hash[table_name] = [info]}
        
        to_db(CnsDb::SimpleDb::PutAttributeSignal.new(publisher, @db, "#{@table_prefix}_schema", "schema_info", hash))
      end
      
      def to_db signal, request = nil
        #CnsBase.logger.fatal signal.pretty_inspect
        
        if request
          request.defer!(
            publisher, 
            CnsBase::Address::AddressRouterSignal.new(
              signal,
              CnsBase::Address::PublisherSignalAddress.new(publisher),
              CnsBase::Address::URISignalAddress.new(@simple_db_url)
            )
          )
        else
          publisher.publish(
            CnsBase::Address::AddressRouterSignal.new(
              signal,
              CnsBase::Address::PublisherSignalAddress.new(publisher),
              CnsBase::Address::URISignalAddress.new(@simple_db_url)
            )
          )
        end
      end
    end
  end
end
