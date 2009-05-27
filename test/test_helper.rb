require 'stringio'
require 'test/unit'
require File.dirname(__FILE__) + '/../lib/cns_db'

class TestDbCore < CnsBase::Cluster::ClusterCore
  def initialize publisher
    super publisher
  end
  
  def dispatch signal
    if signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.deferred_response? && signal.raise_on_deferred_error!
      response = signal.deferrers.first[:response].params
      signal.response = CnsBase::RequestResponse::ResponseSignal.new(:result, response)
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :list_domains
      defer signal, CnsDb::SimpleDb::ListDomainsSignal.new(publisher, "db")
      
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :create_domain
      defer signal, CnsDb::SimpleDb::CreateDomainSignal.new(publisher, "db", signal[:domain])
      
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :delete_domain
      defer signal, CnsDb::SimpleDb::DeleteDomainSignal.new(publisher, "db", signal[:domain])
      
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :query
      defer signal, CnsDb::SimpleDb::QuerySignal.new(publisher, "db", signal[:domain], signal[:query], signal[:max], signal[:token])

    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :get_attribute
      @c ||= 1
      
      (0..@c).each do 
        defer signal, CnsDb::SimpleDb::GetAttributeSignal.new(publisher, "db", signal[:domain], signal[:item])
      end
      
      @c = 1
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :put_attribute
      defer signal, CnsDb::SimpleDb::PutAttributeSignal.new(publisher, "db", signal[:domain], signal[:item], signal[:attributes], signal[:replace])
      
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :delete_attribute
      defer signal, CnsDb::SimpleDb::DeleteAttributeSignal.new(publisher, "db", signal[:domain], signal[:item])
    end
    
    return true
  end
  
  def defer request, signal
    sig = CnsBase::Address::AddressRouterSignal.new(
      signal,
      CnsBase::Address::PublisherSignalAddress.new(publisher),
      CnsBase::Address::URISignalAddress.new("/simpledb")
    )
    
    request.defer! publisher, sig
  end
end

class TestSimpleDbDaoAccessCore < CnsBase::Cluster::ClusterCore
  def initialize publisher
    super publisher
  end
  
  def dispatch signal
    if signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :do
      hash = signal[:hash]
      
      if signal.deferred_response? && signal.raise_on_deferred_error!
        res = signal.deferrers.first[:response]
        
        signal.response = CnsBase::RequestResponse::ResponseSignal.new(:result, {:result => res.hash})
      else
        defer signal, CnsDb::SimpleDbDao::SimpleDbHashRequestSignal.new(publisher, hash)
      end
      
      return true
    elsif signal.is_a?(CnsBase::RequestResponse::RequestSignal) && signal.name == :schema
      hash = signal[:hash]
      
      if signal.deferred_response? && signal.raise_on_deferred_error!
        res = signal.deferrers.first[:response]
        
        signal.response = CnsBase::RequestResponse::ResponseSignal.new(:result, {:result => res.hash})
      else
        defer signal, CnsDb::SimpleDbDao::SchemaInfoSignal.new(publisher)
      end
      
      return true
    end
    
    return false
  end
  
  def defer request, signal
    sig = CnsBase::Address::AddressRouterSignal.new(
      signal,
      CnsBase::Address::PublisherSignalAddress.new(publisher),
      CnsBase::Address::URISignalAddress.new("/simpledbdao_access")
    )
    
    request.defer! publisher, sig
  end
end

class TestSimpleDbDaoAccess < CnsBase::Stub::StubAccessSupport
  cns_method :do, [:hash] do |name, params|
    params[:result]
  end

  cns_method :schema do |name, params|
    params
  end
  
  def initialize
    super "/simpledbdao_access_test"
  end
end

class TestDbAccess < CnsBase::Stub::StubAccessSupport
  cns_method :list_domains do |name, params|
    params
  end

  cns_method :create_domain, [:domain] do |name, params|
    params
  end
  
  cns_method :delete_domain, [:domain] do |name, params|
    params
  end
  
  cns_method :get_attribute, [:domain, :item] do |name, params|
    params
  end
  
  cns_method :put_attribute, [:domain, :item, :replace, :attributes] do |name, params|
    params
  end
  
  cns_method :delete_attribute, [:domain, :item] do |name, params|
    params
  end
  
  cns_method :query, [:domain, :query, :max, :token] do |name, params|
    params
  end
  
  def initialize
    super "/db_test"
  end
end

INIT_HASH = 
{
  :params => 
  [
    {
      :class => CnsBase::Stub::StubControlClusterCore, 
      :uri => "/synq_access_0"
    },
    {
      :class => TestDbCore,
      :params => {},
      :uri => "/db_test"
    },
    {
      :class => CnsDb::SimpleDb::SimpleDbCore,
      :params => {:mode => :cached, :db => "db", :access_key_id => "test", :secret_access_key => "test", :base_url => "http://localhost:8080"},
      #:params => {:mode => :mem, :db => "db", :access_key_id => "test", :secret_access_key => "test", :base_url => "http://localhost:8080"},
      #:params => {:mode => :nocache, :db => "db", :access_key_id => "test", :secret_access_key => "test", :base_url => "http://localhost:8080"},
      :uri => "/simpledb"
    },
    {
      :class => CnsDb::SimpleDbDao::SimpleDbHashAccessCore,
      :params => {:simple_db_url => "/simpledb", :db => "db", :table_prefix => "test"},
      :uri => "/simpledbdao_access"
    },
    {
      :class => TestSimpleDbDaoAccessCore,
      :params => {},
      :uri => "/simpledbdao_access_test"
    }
  ],
  :class => CnsBase::Cas::ClusterApplicationServer
}
