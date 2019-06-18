# Require the dependencies file to load the vendor libraries
require File.expand_path(File.join(File.dirname(__FILE__), "dependencies"))

class ChefCookbookDeleteV1
  # Prepare for execution by building Hash objects for necessary values and
  # validating the present state.  This method sets the following instance
  # variables:
  # * @input_document - A REXML::Document object that represents the input Xml.
  # * @info_values - A Hash of info names to info values.
  # * @parameters - A Hash of parameter names to parameter values.
  #
  # This is a required method that is automatically called by the Kinetic Task
  # Engine.
  #
  # ==== Parameters
  # * +input+ - The String of Xml that was built by evaluating the node.xml
  #   handler template.
  def initialize(input)
    # Set the input document attribute
    @input_document = REXML::Document.new(input)

    # Retrieve all of the handler info values and store them in a hash variable named @info_values.
    @info_values = {}
    REXML::XPath.each(@input_document, "/handler/infos/info") do |item|
      @info_values[item.attributes["name"]] = item.text.to_s.strip
    end

    # Determine if debug logging is enabled.
    @debug_logging_enabled = @info_values['enable_debug_logging'].downcase == 'yes'
    puts "Logging enabled." if @debug_logging_enabled

    # Retrieve all of the handler parameters and store them in a hash variable named @parameters.
    @parameters = {}
    REXML::XPath.each(@input_document, "/handler/parameters/parameter") do |item|
      @parameters[item.attributes["name"]] = item.text.to_s.strip
    end
  end

  # The execute method gets called by the task engine when the handler's node is processed. It is
  # responsible for performing whatever action the name indicates.
  # If it returns a result, it will be in a special XML format that the task engine expects. These
  # results will then be available to subsequent tasks in the process.
  def execute
    username = @info_values['username']
    begin
      if File.exist?(File.expand_path(@info_values['private_key']))
        private_key = OpenSSL::PKey::RSA.new(File.read(File.expand_path(@info_values['private_key'])))
      else
        private_key = OpenSSL::PKey::RSA.new(@info_values['private_key']
          .gsub("-----BEGIN RSA PRIVATE KEY-----","-----BEGIN RSA PRIVATE KEY-----\r\n")
          .gsub("-----END RSA PRIVATE KEY-----", "\r\n-----END RSA PRIVATE KEY-----")
        )
      end
    rescue Exception => e
      puts e
      raise "Invalid Private Key: The provided private key isn't a valid private key or a valid path to a valid private key on the task server"
    end

    # Attempt to delete the existing Chef
    request_url = "#{@info_values['organization_endpoint']}/cookbooks/#{@parameters['cookbook_name']}/#{@parameters['cookbook_version']}"
    response = chef_request("DELETE",request_url,[],"",username,private_key)

    return "<results/>"
  end

  def chef_request(http_method, url, headers, payload, username, private_key)
    uri = URI(url)
    now = Time.now.utc.iso8601

    # Add the standard headers
    header_map = {}
    header_map["Accept"] = "application/json"
    header_map["Content-Type"] = "application/json" if ["POST","PUT"].include?(http_method.upcase)
    header_map["Host"] = "#{uri.host}:#{uri.port}"
    header_map["X-Chef-Version"] = "11.4.0"
    header_map["X-Ops-Sign"] = "algorithm=sha1;version=1.0;"
    header_map["X-Ops-Server-API-Version"] = "1"
    header_map["X-Ops-Timestamp"] = now
    header_map["X-Ops-UserId"] = username

    # Build the Canonical Request

    # Build the canonical uri
    canonical_uri = uri.path.empty? ? "/" : uri.path
    canonical_uri.squeeze("/").gsub(/\/$/,'')

    # Build the hashed payload
    hashed_payload = Base64.encode64(Digest::SHA1.digest(payload.to_s)).chomp

    header_map["X-Ops-Content-Hash"] = hashed_payload

    # Build the full canonical request based on the previous calculated values
    canonical_request = [
        "Method:#{http_method}",
        "Hashed Path:#{Base64.encode64(Digest::SHA1.digest((canonical_uri))).chomp}",
        "X-Ops-Content-Hash:#{hashed_payload}",
        "X-Ops-Timestamp:#{now}",
        "X-Ops-UserId:#{username}",
    ].join("\n")

    hashed_request = private_key.private_encrypt(canonical_request).chomp
    # Base 64 encodes in 60 character chunks, so split on the newline and create
    # X-Ops-Authorization-N headers for each 60 character chunk
    signature = Base64.encode64(hashed_request)
    signature.split("\n").each_with_index do |auth_part,index|
        header_map["X-Ops-Authorization-#{index+1}"] = auth_part.chomp
    end

    # Print out the debug output for the request if debug logging enabled
    if @debug_logging_enabled
      puts "Making a '#{http_method.upcase}' request to Chef"
      puts "  Url: #{url}"
      puts "  Canonical Request:"
      puts "  =================="
      puts "  #{canonical_request}"

      puts "Header Map:"
      puts "=================="
      puts "  #{header_map}"

      puts "Payload:"
      puts "=================="
      puts "  #{payload}"
    end

    resource = RestClient::Resource.new(url, :headers => header_map)
    begin
      if http_method.upcase == "GET"
        response = resource.get
      elsif http_method.upcase == "POST"
        response = resource.post(payload)
      elsif http_method.upcase == "PUT"
        response = resource.put(payload)
      elsif http_method.upcase == "DELETE"
        response = resource.delete
      else
        raise "'#{http_method}' is not a currently supported HTTP Method in the Chef Request helper."
      end
    rescue Exception => error
      response = error.response
    end
    return response
  end

  def chef_error(response)
    if (response.body != nil || response.body.empty?)
      error = JSON.parse(response.body)
      message = error.has_key?("error") ? error['error'].to_s : response.body
    else
      message = "An error without a message has occured. Error Code: #{response.code}"
    end
    raise message
  end

  ##############################################################################
  # General handler utility functions
  ##############################################################################
  # This is a template method that is used to escape results values (returned in
  # execute) that would cause the XML to be invalid.  This method is not
  # necessary if values do not contain character that have special meaning in
  # XML (&, ", <, and >), however it is a good practice to use it for all return
  # variable results in case the value could include one of those characters in
  # the future.  This method can be copied and reused between handlers.
  def escape(string)
      # Globally replace characters based on the ESCAPE_CHARACTERS constant
      string.to_s.gsub(/[&"><]/) { |special| ESCAPE_CHARACTERS[special] } if string
  end
  # This is a ruby constant that is used by the escape method
  ESCAPE_CHARACTERS = {'&'=>'&amp;', '>'=>'&gt;', '<'=>'&lt;', '"' => '&quot;'}
end
