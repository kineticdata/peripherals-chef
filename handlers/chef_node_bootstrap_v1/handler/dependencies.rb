require 'shellwords'
require 'net/http'
require 'uri'

# If the Kinetic Task version is under 4, load the openssl and json libraries
# because they are not included in the ruby version
if KineticTask::VERSION.split('.').first.to_i < 4
    # Load the ruby json library unless it has already been loaded.  This 
    # prevents multiple handlers using the same library from causing problems.
    if not defined?(JSON)
      # Calculate the location of this file
      handler_path = File.expand_path(File.dirname(__FILE__))
      # Calculate the location of our library and add it to the Ruby load path
      library_path = File.join(handler_path, 'vendor/json-1.8.0/lib')
      $:.unshift library_path
      # Require the library
      require 'json'
    end

    # Validate the the loaded JSON library is the library that is expected for
    # this handler to execute properly.
    if not defined?(JSON::VERSION)
      raise "The JSON class does not define the expected VERSION constant."
    elsif JSON::VERSION.to_s != '1.8.0'
      raise "Incompatible library version #{JSON::VERSION} for JSON.  Expecting version 1.8.0."
    end

    # Load the JRuby Open SSL library unless it has already been loaded.  This
    # prevents multiple handlers using the same library from causing problems.
    if not defined?(Jopenssl)
      # Load the Bouncy Castle library required for Jopenssl.
      handler_path = File.expand_path(File.dirname(__FILE__))
      # Calculate the location of our library and add it to the Ruby load path
      library_path = File.join(handler_path, 'vendor/bouncy-castle-java-1.5.0147/lib')
      $:.unshift library_path
      # Require the library
      require 'bouncy-castle-java'
      
      # Calculate the location of this file
      handler_path = File.expand_path(File.dirname(__FILE__))
      # Calculate the location of our library and add it to the Ruby load path
      library_path = File.join(handler_path, 'vendor/jruby-openssl-0.8.8/lib/shared')
      $:.unshift library_path
      # Require the library
      require 'openssl'
      # Require the version constant
      require 'jopenssl/version'
    end

    # Validate the the loaded openssl library is the library that is expected for
    # this handler to execute properly.
    if not defined?(Jopenssl::Version::VERSION)
      raise "The Jopenssl class does not define the expected VERSION constant."
    elsif Jopenssl::Version::VERSION != '0.8.8'
      raise "Incompatible library version #{Jopenssl::Version::VERSION} for Jopenssl.  Expecting version 0.8.8"
    end
end


# Check the operating system the handler is being run on. If the handler is
#   a version of windows, it will load the JRuby Pageant Gem, if it has not
#   been loaded already.
require 'rbconfig'
if Config::CONFIG['target_os'] =~ /mswin/
  if not defined?(JRubyPageant)
    # Calculate the location of this file
    handler_path = File.expand_path(File.dirname(__FILE__))
    # Calculate the location of our library and add it to the Ruby load path
    library_path = File.join(handler_path, 'vendor/jruby-pageant-1.1.1-java/lib-java')
    $:.unshift library_path
    # Require the library
    require 'jruby_pageant'
    module JRubyPageant; VERSION = '1.1.1'; end
  else 
    # Validate the the loaded JRubyPageant library is the library that is expected
    # for this handler to execute properly.
    if not defined?(JRubyPageant::VERSION)
      raise "The JRubyPageant module does not define the expected VERSION constant."
    elsif JRubyPageant::VERSION != '1.1.1'
      raise "Incompatible library version #{JRubyPageant::VERSION} for JRubyPageant.  Expecting version 1.1.1."
    end
  end
end

# Loads the net-ssh library if it has not already been loaded.
if not defined?(Net::SSH)
  # Calculate the location of this file
  handler_path = File.expand_path(File.dirname(__FILE__))
  # Calculate the location of our library and add it to the Ruby load path
  library_path = File.join(handler_path, 'vendor/net-ssh')
  $:.unshift library_path
  # Require the library
  require 'net/ssh'
end

# Validate the the loaded openssl library is the library that is expected for
# this handler to execute properly.
if not defined?(Net::SSH::Version::STRING)
  raise "The Net-SSH class does not define the expected VERSION constant."
elsif Net::SSH::Version::STRING.to_s != '2.6.7'
  raise "Incompatible library version #{Net::SSH::Version::STRING} for Net-SSH.  Expecting version 2.6.7."
end
