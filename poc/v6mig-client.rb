#!/usr/bin/env ruby

require "json"
require "net/http"
require "optparse"
require "resolv"
require "timeout"

$domain = "v6mig.example.jp"
$supported_protocol = [ 'DS-Lite', 'IPIP' ]
$redirect_limit = 5
$dns_timeout = 5

$cacert = <<CERT  # Let's Encrypt
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
CERT


def dns_lookup()
  puts "provisioning domain name is: #{$domain}"
  txt = nil

  resolver = Resolv::DNS.new()

  begin
    Timeout.timeout($dns_timeout) do
      txt = resolver.getresource($domain, Resolv::DNS::Resource::IN::TXT)
    end
  rescue Resolv::ResolvError
    puts "DNS lookup failed: #{$domain}"
    return nil
  rescue Timeout::Error
    puts "DNS timeout"
    return nil
  ensure
    def resolver.servers()
      return @config.nameserver_port.map(&:first).join(", ")
    end
    puts "name servers are: #{resolver.servers()}"
  end
  return txt.data
end

def parse_location(txt)
  if txt =~ /v=v6mig-1 url=(http[^ ]+) t=([abc])/
    return { :url => $1, :type => $2 }
  else
    puts "error: invalid provisioning locator: #{txt}"
    return nil
  end
end

def make_cert_store()
  cert = OpenSSL::X509::Certificate.new($cacert)
  store = OpenSSL::X509::Store.new()
  store.add_cert(cert)
  return store
end

def http_get(loc)
  uri = URI.parse(loc[:url])
  puts "retrieve provisioning config from: #{uri.to_s}"

  config = nil
  $redirect_limit.times { |i|
    http = Net::HTTP.new(uri.host, uri.port)
    if loc[:type] != "a"
      http.use_ssl = true
    end

    http.cert_store = make_cert_store()

    begin
      response = http.get(uri.path)
      case response.code
      when /^2/
        return response.body
      when /^3/
        uri = URI.parse(response['location'])
        next
      else
        puts "error: unexpected HTTP response code: #{response.code}"
        return nil
      end
    rescue OpenSSL::SSL::SSLError => e
      puts "error: cannot establish secure connection to server: #{e.message}"
      return nil
    end
  }
  puts "error: too many redirections (>= #{$redirect_limit})"
  return nil
end

def setup_dslite(aftr)
  puts "exec: ip -6 tunnel add dslite0 mode ip4ip6 remote #{aftr} local ..."
  puts "exec: ip -4 route add default dev dslite0"
end

def stop_mig()
  puts "exec: ip -4 route delete default dev dslite0"
  puts "exec: ip -6 tunnel delete dslite0"
end

def sleep_retry(min, max)
  m = rand(min..max)
  puts "retry: sleep #{m} minutes"
  sleep m * 60
end

def mainloop()
  loop do
    # a), b), c)
    txt = dns_lookup()
    if txt
      puts "provisioning server locator is: #{txt}"
    else
      sleep_retry(1, 10)
      next
    end

    loc = parse_location(txt)
    unless loc
      sleep_retry(1, 10)
      next
    end

    # d), e), f)
    config = http_get(loc)
    unless config
      sleep_retry(10, 30)
      next
    end

    # g)
    puts "provisioning config: #{config.size} bytes"
    puts "---"
    puts config.rstrip
    puts "---"

    # h)
    begin
      json = JSON.parse(config)
    rescue JSON::JSONError
      puts "error: invalid json"
      stop_mig()
      sleep_retry(10, 30)
      next
    end

    # i)
    services = json["order"]
    unless services
      puts "error: \"order\" is missing"
      exit 1
    end

    # k)
    services.each { |name|
      puts "configuring #{name}"

      case name
      when "dslite"
        dslite = json[name]
        unless dslite
          puts "error: no #{name} config"
          exit 1
        end
        setup_dslite(dslite["aftr"])
        break

      when "map_e"
        puts "#{name} is not supported.  skip it."

      else
        puts "error: unknown service name \"#{name}\""
        exit 1
      end
    }

    # l)
    puts "provisioning succeeded"
    if json.has_key? "ttl"
      ttl = json["ttl"] / 60.0
      sleep_retry(ttl, ttl)
    else
      sleep_retry(20*60, 24*60)
    end
  end
end

def usage
  puts "usage: #{$0} [--cacert <cert>] <provisioning-domain-name>"
end


if __FILE__ == $0  # main routine
  opt = OptionParser.new
  opt.on('--cacert FILENAME') { |v| $cacert = File.read(v) }
  #opt.on('--domain DOMAIN') { |v| $domain = v }
  opt.parse!(ARGV)

  if ARGV.size != 1
    usage
    exit 1
  end
  $domain = ARGV[0]

  mainloop()
end
