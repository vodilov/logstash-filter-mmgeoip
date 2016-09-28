# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require "logstash-filter-mmgeoip_jars"

java_import "java.net.InetAddress"
java_import "com.maxmind.geoip2.DatabaseReader"
java_import "com.maxmind.geoip2.model.CityResponse"
java_import "com.maxmind.geoip2.record.Country"
java_import "com.maxmind.geoip2.record.Subdivision"
java_import "com.maxmind.geoip2.record.City"
java_import "com.maxmind.geoip2.record.Postal"
java_import "com.maxmind.geoip2.record.Location"
java_import "com.maxmind.db.CHMCache"

def suppress_all_warnings
  old_verbose = $VERBOSE
  begin
    $VERBOSE = nil
    yield if block_given?
  ensure
    # always re-set to old value, even if block raises an exception
    $VERBOSE = old_verbose
  end
end

# create a new instance of the Java class File without shadowing the Ruby version of the File class
module JavaIO
  include_package "java.io"
end


# The GeoIP2 filter adds information about the geographical location of IP addresses,
# based on data from the Maxmind database.
#
# Starting with version 1.3.0 of Logstash, a `[geoip][location]` field is created if
# the GeoIP lookup returns a latitude and longitude. The field is stored in
# http://geojson.org/geojson-spec.html[GeoJSON] format. Additionally,
# the default Elasticsearch template provided with the
# <<plugins-outputs-elasticsearch,`elasticsearch` output>> maps
# the `[geoip][location]` field to an http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/mapping-geo-point-type.html#_mapping_options[Elasticsearch geo_point].
#
# As this field is a `geo_point` _and_ it is still valid GeoJSON, you get
# the awesomeness of Elasticsearch's geospatial query, facet and filter functions
# and the flexibility of having GeoJSON for all other applications (like Kibana's
# map visualization).
#
# This product includes GeoLite2 data created by MaxMind, available from
# <http://dev.maxmind.com/geoip/geoip2/geolite2/>.
class LogStash::Filters::MMGeoIP < LogStash::Filters::Base
  config_name "mmgeoip"

  # The path to the GeoIP2 database file which Logstash should use.
  config :database, :validate => :path, :required => true

  # GeoIP2 database type
  #
  # Supported:
  # `city` (default), `country`, `anonymous_ip`, `connection_type`, `domain`, `enterprise`, `isp`
  config :database_type, :validate => :string, :default => 'city'

  # The field containing the IP address or hostname to map via geoip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all geoip fields
  # are included in the event.
  #
  # For the GeoIP2 LiteCity database, the following are available:
  # `city_name`, `continent_code`, `country_code2`, `country_code3`, `country_name`,
  # `dma_code`, `ip`, `latitude`, `longitude`, `postal_code`, `region_name` and `timezone`.
  config :fields, :validate => :array

  # Specify the field into which Logstash should store the geoip data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the GeoIP information of both IPs.
  #
  # If you save the data to a target field other than `geoip` and want to use the
  # `geo\_point` related functions in Elasticsearch, you need to alter the template
  # provided with the Elasticsearch output and configure the output to use the
  # new template.
  #
  # Even if you don't use the `geo\_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'geoip'

  # GeoIP lookup is surprisingly expensive. This filter uses an cache to take advantage of the fact that
  # IPs agents are often found adjacent to one another in log files and rarely have a random distribution.
  # The higher you set this the more likely an item is to be in the cache and the faster this filter will run.
  # However, if you set this too high you can use more memory than desired.
  # Since the Geoip API upgraded to v2, there is not any eviction policy so far, if cache is full, no more record can be added.
  # Experiment with different values for this option to find the best performance for your dataset.
  #
  # This MUST be set to a value > 0. There is really no reason to not want this behavior, the overhead is minimal
  # and the speed gains are large.
  #
  # It is important to note that this config value is global to the geoip_type. That is to say all instances of the geoip filter
  # of the same geoip_type share the same cache. The last declared cache size will 'win'. The reason for this is that there would be no benefit
  # to having multiple caches for different instances at different points in the pipeline, that would just increase the
  # number of cache misses and waste memory.
  config :cache_size, :validate => :number, :default => 1000

  # GeoIP lookup is surprisingly expensive. This filter uses an LRU cache to take advantage of the fact that
  # IPs agents are often found adjacent to one another in log files and rarely have a random distribution.
  # The higher you set this the more likely an item is to be in the cache and the faster this filter will run.
  # However, if you set this too high you can use more memory than desired.
  #
  # Experiment with different values for this option to find the best performance for your dataset.
  #
  # This MUST be set to a value > 0. There is really no reason to not want this behavior, the overhead is minimal
  # and the speed gains are large.
  #
  # It is important to note that this config value is global to the geoip_type. That is to say all instances of the geoip filter
  # of the same geoip_type share the same cache. The last declared cache size will 'win'. The reason for this is that there would be no benefit
  # to having multiple caches for different instances at different points in the pipeline, that would just increase the
  # number of cache misses and waste memory.
  config :lru_cache_size, :validate => :number, :default => 1000

  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_geoip_lookup_failure"]

  public
  def register
    suppress_all_warnings do
      if @database.nil? || !File.exists?(@database)
        raise "You must specify 'database => ...' in your geoip filter (I looked for '#{@database}')"
      end

      case @database_type
        when "city"
          if @fields.nil?
            @fields = Array[
                'city_name', 'continent_name', 'continent_code',
                'country_name', 'country_code1', 'country_code2', 'country_code3',
                'latitude', 'longitude', 'dma_code', 'postal_code', 'region_name', 'region_code', 'timezone', 'location', 'ip'
            ]
          end
        when "country"
          if @fields.nil?
            @fields = Array['continent_name', 'continent_code1', 'country_code2', 'country_code3', 'country_code', 'country_name', 'ip']
          end
        when "anonymous_ip"
          if @fields.nil?
            @fields = Array['is_anonymous', 'is_anonymous_vpn', 'is_hosting_provider', 'is_public_proxy', 'is_tor_exit_node', 'ip']
          end
        when "connection_type"
          if @fields.nil?
            @fields = Array['connection_type', 'ip']
          end
        when "domain"
          if @fields.nil?
            @fields = Array['domain', 'ip']
          end
        when "enterprise"
          if @fields.nil?
            @fields = Array['city_name', 'continent_name', 'continent_code', 'country_code2', 'country_code3', 'country_code1', 'country_name',
                            'dma_code', 'ip', 'latitude', 'longitude', 'postal_code', 'region_name', 'region_code', 'timezone', 'location',
                            'connection_type', 'domain', 'is_anonymous_proxy', 'is_legitimate_proxy', 'is_satellite_provider', 'isp', 'organization', 'user_type',
                            'autonomous_system_number', 'autonomous_system_organization']
          end
        when "isp"
          if @fields.nil?
            @fields = Array['ip', 'isp', 'organization', 'autonomous_system_number', 'autonomous_system_organization']
          end
        else
          raise "You must specify correct 'database_type => ...' in your geoip filter (I see '#{@database_type}')"
      end

      @logger.info("Using geoip database", :path => @database)

      db_file = JavaIO::File.new(@database)
      begin
        @parser = DatabaseReader::Builder.new(db_file).withCache(CHMCache.new(@cache_size)).build();
      rescue Java::ComMaxmindDb::InvalidDatabaseException => e
        @logger.error("The Geoip2 MMDB database provided is invalid or corrupted.", :exception => e, :field => @source)
        raise e
      end
    end
  end

  # def register

  public
  def filter(event)
    return unless filter?(event)

    begin
      ip = event[@source]
      ip = ip.first if ip.is_a? Array
      geo_data_hash = Hash.new
      ip_address = InetAddress.getByName(ip)

      case @database_type
        when "city"
          response = @parser.city(ip_address)
          populate_geo2_data_city(response, ip_address, geo_data_hash)
        when "country"
          response = @parser.country(ip_address)
          populate_geo2_data_country(response, ip_address, geo_data_hash)
        when "anonymous_ip"
          response = @parser.anonymousIp(ip_address)
          populate_geo2_data_anonymous_ip(response, ip_address, geo_data_hash)
        when "connection_type"
          response = @parser.connectionType(ip_address)
          populate_geo2_data_connection_type(response, ip_address, geo_data_hash)
        when "domain"
          response = @parser.domain(ip_address)
          populate_geo2_data_domain(response, ip_address, geo_data_hash)
        when "enterprise"
          response = @parser.enterprise(ip_address)
          populate_geo2_data_enterprise(response, ip_address, geo_data_hash)
        when "isp"
          response = @parser.isp(ip_address)
          populate_geo2_data_isp(response, ip_address, geo_data_hash)
      end

    rescue com.maxmind.geoip2.exception.AddressNotFoundException => e
      @logger.debug("IP not found!", :exception => e, :field => @source, :event => event)
    rescue java.net.UnknownHostException => e
      @logger.error("IP Field contained invalid IP address or hostname", :exception => e, :field => @source, :event => event)
    rescue Exception => e
      @logger.error("Unknown error while looking up GeoIP data", :exception => e, :field => @source, :event => event)
      # Dont' swallow this, bubble up for unknown issue
      raise e
    end

    if geo_data_hash.empty?
      tag_unsuccessful_lookup(event)
      return
    end

    if event[@target].nil?
      event[@target] = geo_data_hash
    else
      geo_data_hash.each do |key, value|
        event["[#{@target}][#{key}]"] = value
      end # geo_data_hash.each
    end

    filter_matched(event)
  end

  # def filter

  def populate_geo2_data_city(response, ip_address, geo_data_hash)
    subdivision = response.getMostSpecificSubdivision()
    location = response.getLocation()

    # if location is empty, there is no point populating geo data
    # and most likely all other fields are empty as well
    if location.getLatitude().nil? && location.getLongitude().nil?
      return
    end

    @fields.each do |field|
      case field
        when "continent_code"
          geo_data_hash[field] = response.getContinent().getCode()
        when "continent_name"
          geo_data_hash[field] = response.getContinent().getName()
        when "city_name"
          geo_data_hash[field] = response.getCity().getName()
        when "country_name"
          geo_data_hash[field] = response.getCountry().getName()
        when "country_code1"
          geo_data_hash[field] = response.getCountry().getIsoCode()
        when "country_code2"
          geo_data_hash[field] = response.getRegisteredCountry().getIsoCode()
        when "country_code3"
          geo_data_hash[field] = response.getRepresentedCountry().getIsoCode()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        when "postal_code"
          geo_data_hash[field] = response.getPostal().getCode()
        when "dma_code"
          geo_data_hash[field] = location.getMetroCode()
        when "region_name"
          geo_data_hash[field] = subdivision.getName()
        when "region_code"
          geo_data_hash[field] = subdivision.getIsoCode()
        when "timezone"
          geo_data_hash[field] = location.getTimeZone()
        when "location"
          geo_data_hash[field] = [location.getLongitude(), location.getLatitude()]
        when "latitude"
          geo_data_hash[field] = location.getLatitude()
        when "longitude"
          geo_data_hash[field] = location.getLongitude()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_country(response, ip_address, geo_data_hash)
    @fields.each do |field|
      case field
        when "continent_code"
          geo_data_hash[field] = response.getContinent().getCode()
        when "continent_name"
          geo_data_hash[field] = response.getContinent().getName()
        when "country_name"
          geo_data_hash[field] = response.getCountry().getName()
        when "country_code1"
          geo_data_hash[field] = response.getCountry().getIsoCode()
        when "country_code2"
          geo_data_hash[field] = response.getRegisteredCountry().getIsoCode()
        when "country_code3"
          geo_data_hash[field] = response.getRepresentedCountry().getIsoCode()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_anonymous_ip(response, ip_address, geo_data_hash)
    @fields.each do |field|
      case field
        when "is_anonymous"
          geo_data_hash[field] = response.isAnonymous()
        when "is_anonymous_vpn"
          geo_data_hash[field] = response.isAnonymousVpn()
        when "is_hosting_provider"
          geo_data_hash[field] = response.isHostingProvider()
        when "is_public_proxy"
          geo_data_hash[field] = response.isPublicProxy()
        when "is_tor_exit_node"
          geo_data_hash[field] = response.isTorExitNode()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_connection_type(response, ip_address, geo_data_hash)
    @fields.each do |field|
      case field
        when "connection_type"
          if !response.getConnectionType().nil?
            geo_data_hash[field] = response.getConnectionType().toString()
          else
            geo_data_hash[field] = nil
          end
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_domain(response, ip_address, geo_data_hash)
    @fields.each do |field|
      case field
        when "domain"
          geo_data_hash[field] = response.getDomain()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_enterprise(response, ip_address, geo_data_hash)
    subdivision = response.getMostSpecificSubdivision()
    location = response.getLocation()
    traits = response.getTraits()

    # if location is empty, there is no point populating geo data
    # and most likely all other fields are empty as well
    if location.getLatitude().nil? && location.getLongitude().nil?
      return
    end

    @fields.each do |field|
      case field
        when "continent_code"
          geo_data_hash[field] = response.getContinent().getCode()
        when "continent_name"
          geo_data_hash[field] = response.getContinent().getName()
        when "city_name"
          geo_data_hash[field] = response.getCity().getName()
        when "country_name"
          geo_data_hash[field] = response.getCountry().getName()
        when "country_code1"
          geo_data_hash[field] = response.getCountry().getIsoCode()
        when "country_code2"
          geo_data_hash[field] = response.getRegisteredCountry().getIsoCode()
        when "country_code3"
          geo_data_hash[field] = response.getRepresentedCountry().getIsoCode()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        when "postal_code"
          geo_data_hash[field] = response.getPostal().getCode()
        when "dma_code"
          geo_data_hash[field] = location.getMetroCode()
        when "region_name"
          geo_data_hash[field] = subdivision.getName()
        when "region_code"
          geo_data_hash[field] = subdivision.getIsoCode()
        when "timezone"
          geo_data_hash[field] = location.getTimeZone()
        when "location"
          geo_data_hash[field] = [location.getLongitude(), location.getLatitude()]
        when "latitude"
          geo_data_hash[field] = location.getLatitude()
        when "longitude"
          geo_data_hash[field] = location.getLongitude()
        when "connection_type"
          if !response.getConnectionType().nil?
            geo_data_hash[field] = response.getConnectionType().toString()
          else
            geo_data_hash[field] = nil
          end
        when "domain"
          geo_data_hash[field] = traits.getDomain()
        when "is_anonymous_proxy"
          geo_data_hash[field] = traits.isAnonymousProxy()
        when "is_legitimate_proxy"
          geo_data_hash[field] = traits.isLegitimateProxy()
        when "is_satellite_provider"
          geo_data_hash[field] = traits.isSatelliteProvider()
        when "isp"
          geo_data_hash[field] = traits.getIsp()
        when "organization"
          geo_data_hash[field] = traits.getOrganization()
        when "user_type"
          geo_data_hash[field] = traits.getUserType()
        when "autonomous_system_number"
          geo_data_hash[field] = traits.getAutonomousSystemNumber()
        when "autonomous_system_organization"
          geo_data_hash[field] = traits.getAutonomousSystemOrganization()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end

  def populate_geo2_data_isp(response, ip_address, geo_data_hash)
    @fields.each do |field|
      case field
        when "isp"
          geo_data_hash[field] = response.getIsp()
        when "organization"
          geo_data_hash[field] = response.getOrganization()
        when "autonomous_system_number"
          geo_data_hash[field] = response.getAutonomousSystemNumber()
        when "autonomous_system_organization"
          geo_data_hash[field] = response.getAutonomousSystemOrganization()
        when "ip"
          geo_data_hash[field] = ip_address.getHostAddress()
        else
          raise Exception.new("[#{field}] is not a supported field option.")
      end
    end
  end


  def tag_unsuccessful_lookup(event)
    @logger.debug? && @logger.debug("IP #{event[@source]} was not found in the database", :event => event)
    @tag_on_failure.each { |tag| event.tag(tag) }
  end

end # class LogStash::Filters::MMGeoIP
