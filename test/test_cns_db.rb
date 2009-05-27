require File.dirname(__FILE__) + '/test_helper.rb'

$A = 0

class TestCnsDb < Test::Unit::TestCase

  def setup
    CnsBase::Cas::CasControlHelper.shutdown
  end

  def test_db
    CnsBase::Cas::CasControlHelper.init INIT_HASH
    CnsBase::Cas::CasControlHelper.confirm_start
    
    dao = TestDbAccess.new

    puts "1"
    puts "2"
    pp dao.list_domains
    puts "3"
    pp dao.create_domain("sweetapp_development")
    puts "4"
    pp dao.list_domains
    puts "5"
    pp dao.create_domain("sweetapp_development")
    puts "6"
    pp dao.list_domains
    puts "7"
    pp dao.delete_domain("sweetapp_development")
    puts "8"
    pp dao.list_domains
    puts "9"
    
    CnsBase.logger.level = Logger::FATAL
    begin
      dao.put_attribute("sweetapp_development", "1", true, {:as => [22, -11], :boo => ["hhkhhjj"*1], :hi => ["方法"]})
      assert false
    rescue => exception
      puts exception.class.name
      puts exception.message
    end
    CnsBase.logger.level = Logger::INFO

    puts "a"

    pp dao.delete_domain("sweetapp_development")
    pp dao.create_domain("sweetapp_development")
    puts "b"
    dao.put_attribute("sweetapp_development", "1", true, {:as => [22, -11], :ga => [Time.now], :boo => ["hhkhhjj>"*1], :hi => ["方法"]})
    puts "c"
    pp dao.get_attribute("sweetapp_development", "1")
    puts Time.now
    pp dao.get_attribute("sweetapp_development", "1")
    puts Time.now
    puts "d"
    pp dao.delete_attribute("sweetapp_development", "1")
    puts "e"
    pp dao.get_attribute("sweetapp_development", "1")

    dao.put_attribute("sweetapp_development", "1", true, {:as => [22, -11], :ga => [Time.now], :boo => ["hhkhhjj"*1], :hi => ["方法"]})
    pp dao.query("sweetapp_development", "['as' = '22']", nil, nil)
    pp dao.query("sweetapp_development", ["[? = ?]", :as, 22], nil, nil)
    pp dao.query("sweetapp_development", ["[? > ?]", :ga, (Time.now+50)], nil, nil)
    pp dao.query("sweetapp_development", ["[? > ?]", :ga, (Time.now-50)], nil, nil)

    CnsBase::Cas::CasControlHelper.shutdown

    puts
    puts
    puts
    puts
    puts
  end

  def test_dao_access
    CnsBase::Cas::CasControlHelper.init INIT_HASH
    CnsBase::Cas::CasControlHelper.confirm_start

    dao = TestDbAccess.new
    
    dao.delete_domain "test_schema"
    dao.delete_domain "test_data_1"
    dao.create_domain "test_schema"
    dao.create_domain "test_data_1"
    
    simpledbdao = TestSimpleDbDaoAccess.new
    pp(simpledbdao.schema)

    puts
    puts
    puts
    puts
    puts

    puts "create 2 new data sets"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias] << {:name => ["Hello"]}
    hash[:medias] << {:name => ["Hoho", "Hillo"]}
    pp hash.get
    res = simpledbdao.do(hash)
    id = res[:medias].keys.first
    id2 = res[:medias].keys.last
    pp res
    
    puts
    puts
    puts
    puts
    puts

    
    puts "get all data from medias"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias]
    pp hash.get
    pp(simpledbdao.do(hash))
    
    sleep 2
    
    puts
    puts
    puts
    puts
    puts


    puts "edit id #{id} and #{id2} and non existing 100000"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][id][:hoge] = [1,2,3]
    hash[:medias][id][:bla] = [1,2,4]
    hash[:medias][id][:created_at] = [1,2,3]
    hash[:medias][id] = {:foo => [:foo]}
    hash[:medias][id2] = {:foo2 => [Time.now, {:hello => :hoho}]}
    hash[:medias][100000] = {:foo3 => [Time.now, {:hello => :hoho}]}
    pp hash.get
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts
    
    sleep 1

    puts "get all data from medias"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias]
    pp hash.get
    pp(simpledbdao.do(hash))

    
    puts
    puts
    puts
    puts
    puts

    puts "delete id #{id2} and not existing 10000"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][id2].delete
    puts "NOTE: skipping 10000 delete"
#    hash[:medias][10000].delete
    pp hash.get
    pp(simpledbdao.do(hash))

    
    puts
    puts
    puts
    puts
    puts

    puts "get all data from medias"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias]
    pp hash.get
    pp(simpledbdao.do(hash))

    puts
    puts
    puts
    puts
    puts

    puts "get only name from media 2"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][id][:name]
    pp hash.get
    pp(simpledbdao.do(hash))

    puts
    puts
    puts
    puts
    puts

    puts "get only sw Hell"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][:name].starts_with "Hi"
    pp hash.get
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts

    puts "get only future"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][:created_at] > Time.now
    pp hash.get
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts

    puts "get only past"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][:created_at] <= Time.now
    pp hash.get
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts

    puts "get only names"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][:name]
    pp hash.get
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts

    puts "get #{id}"
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][id]
    pp(simpledbdao.do(hash))
    
    puts
    puts
    puts
    puts
    puts
    
    puts Time.now

    puts "add big file"
    big_data = "*" * 1000000
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias] << {:file => [big_data, big_data]}
    puts "send at #{Time.now}"
    res = simpledbdao.do(hash)
    puts "responded at #{Time.now}"
    pp res
    puts Time.now
    id = res[:medias].keys.first

    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:medias][id]
    puts "get at #{Time.now}"
    res = simpledbdao.do(hash)
    puts "responded at #{Time.now}"
    
    pp res

    puts "start to load at #{Time.now}"
    obj = res[:medias][id][:file][0]
    puts "finished loading #{Time.now}"

    puts obj.class.name
    puts obj.size
    puts obj[0..100]

  puts "create user and venue"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash[:users] << {:hello => ["hoho"]}
  hash[:venues] << {:cool => [true]}
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)
  user_id = res[:users].keys.first
  venue_id = res[:users].keys.first

  puts "get user and venue"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash[:users][user_id]
  hash[:venues][venue_id]
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)

  puts "connect user and venue"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.connect! :owner, [[:users, user_id]], [[:venues, venue_id]]
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)
  rel_id = res[:relations].keys.first
  
  puts "get user connections"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.connection :owner, :users, user_id, :left
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)

  puts "get user connections objects"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.rows_of_connection res, :right
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)
  
  puts "get venue connections"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.connection :owner, :venues, venue_id, :right
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)

  puts "get venue connections objects"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.rows_of_connection res, :left
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)
  
  puts "unconnect user and venue"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.unconnect! rel_id
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)

  puts "get user connections"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.connection :owner, :users, user_id, :both
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)
  
  puts "get venue connections"
  hash = CnsDb::SimpleDbDao::SimpleDbHash.new
  hash.connection :owner, :venues, venue_id, :both
  pp hash.get
  res = simpledbdao.do(hash)
  pp(res)

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

=begin
    puts Time.now
    
    single_test(simpledbdao)

    puts Time.now
    puts "START"

    (0..50).each do
      Thread.new {single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao);single_test(simpledbdao)}
    end
    
    while $A < 480
      sleep 1
    end

    puts Time.now
=end
    CnsBase::Cas::CasControlHelper.shutdown
  end
  
  private
  def single_test simpledbdao
    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:users] << {:hello => ["hoho"]}
    hash[:venues] << {:cool => [true]}
    hash.get
    res = simpledbdao.do(hash)
    user_id = res[:users].keys.first
    venue_id = res[:users].keys.first
    
    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash[:users][user_id]
    hash[:venues][venue_id]
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.connect! :owner, [[:users, user_id]], [[:venues, venue_id]]
    hash.get
    res = simpledbdao.do(hash)
    rel_id = res[:relations].keys.first

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.connection :owner, :users, user_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.rows_of_connection res, :users, user_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.connection :owner, :venues, venue_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.rows_of_connection res, :venues, venue_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.unconnect! rel_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.connection :owner, :users, user_id
    hash.get
    res = simpledbdao.do(hash)

    print "."
    hash = CnsDb::SimpleDbDao::SimpleDbHash.new
    hash.connection :owner, :venues, venue_id
    hash.get
    res = simpledbdao.do(hash)
    
    $A += 1
  end
end
