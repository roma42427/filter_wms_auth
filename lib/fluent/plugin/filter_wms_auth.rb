require 'base64'
require 'fluent/plugin/filter'

class WmsAuth < Fluent::Plugin::Filter
  Fluent::Plugin.register_filter('wms_auth', self)
  HOST = Socket.gethostname

  def filter(tag, time, record)
    record['host'.freeze] = HOST

    path = record['path'.freeze]
    if path.sub! /wmsAuthSign=([^&]+)&?/, ''.freeze
      id,cookie,_ = Base64.decode64($1)[/id=([^&]+)/, 1].split('+'.freeze,3)
      record['user_id'.freeze] = id.to_i unless id.empty?
      record['cookie'.freeze] = cookie
    end
    if path.sub! /nimblesessionid=([^&]+)&?/, ''.freeze
      record['nimble_session_id'.freeze] = $1
    end
    record
  end
end
