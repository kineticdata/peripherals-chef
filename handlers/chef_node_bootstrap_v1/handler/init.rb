require File.expand_path(File.join(File.dirname(__FILE__), 'dependencies'))

class ChefNodeBootstrapV1
  def initialize(input)
    # Set the input document attribute
    @input_document = REXML::Document.new(input)

    # Store the info values in a Hash of info names to values.
    @info_values = {}
    REXML::XPath.each(@input_document,"/handler/infos/info") { |item|
      @info_values[item.attributes['name']] = item.text  
    }

    # Retrieve all of the handler parameters and store them in a hash attribute
    # named @parameters.
    @parameters = {}
    REXML::XPath.match(@input_document, 'handler/parameters/parameter').each do |node|
      @parameters[node.attribute('name').value] = node.text.to_s
    end
  end
  
  def execute()
    resources_path = File.join(File.expand_path(File.dirname(__FILE__)), 'resources')

    # Create a hash of the variables that will be passed to the knife
    # ruby script as a json string
    params = {
      "server_name" => @parameters['server_name'],
      "user_config" => @parameters['user_config'],
      "node_name" => @parameters['node_name'],
      "recipe" => @parameters['recipe'],
      "source_name" => @parameters['source_name'],
      "knife_location" => @info_values['knife_location'],
      "task_location" => @info_values['task_location'],
      "deferral_token" => @parameters['deferral_token']
    }

    # Check for obvious errors before passing the information to the 
    # external ruby script
    if Config::CONFIG['target_os'] =~ /mswin/
      # Accept the EULA on PsExec.exe if it is not installed
      puts "Loading PsExec.exe"
      puts `cd "#{resources_path}" & PsExec.exe /accepteula`
      puts "PsExec.exe finished loading"

      # Check to see if knife is included in the chef repo
      code = `cd #{resources_path} & if EXIST "#{@info_values['knife_location']}" echo 200`
      
      if code.strip != "200"
        raise StandardError, "knife.rb not found in the inputted location: '#{@info_values['knife_location']}'. If located in the resources directory, make sure there is no leading '/' on the path."
      end

      # Check to see if the json gem is installed
      json_output = ""
      STDOUT.sync = true
      IO.popen("cd \"#{resources_path}\" & ruby test_json.rb 2>&1") do |pipe|
        pipe.sync = true
        while str = pipe.gets
          json_output += str
        end
      end
      
      if json_output != ""
        puts "Error attempting to run ruby file requiring JSON: Console output for command is below"
        puts json_output
        raise StandardError, "JSON not installed in the external ruby instance. Make sure external ruby instance and the json gem are both installed."
      else
        puts "JSON installation successfully found in the external ruby instance."
      end

    else
      # Check to see if json is installed for the external ruby instance
        ret = system("cd #{resources_path}; ruby test_json.rb")
        puts "Testing ret: #{ret}"
        if $? != 0
          raise StandardError, "JSON not installed in the external ruby instance. Make sure external ruby instance and the json gem are both installed."
        else
          puts "JSON installation successfully found in the external ruby instance."
        end

      # Check to see if knife is included in the chef repo
      code = `cd #{resources_path}; [ -f #{@info_values['knife_location']} ] && echo "200" || echo "404"`

      if code.strip != "200"
        raise StandardError, "knife.rb not found in the inputted location: '#{@info_values['knife_location']}'. If located in the resources directory, make sure there is no leading '/' on the path."
      end
      puts "Knife.rb configuration file successfully found."
    end

    res = nil
    # Check with net/http to see if the task server and source name exist
    if params["task_location"].match(/kinetic-task\/*$/) != nil 
      # Having kinetic-task in the url means to use the Task 4 api
      puts "Kinetic Task 4 detected"

      path = "/app/api/v1/sources/#{params["source_name"]}/runs"
      endpoint = URI(params["task_location"].gsub(/\/+$/,"") + path)

      req = Net::HTTP::Get.new endpoint.to_s
      res = Net::HTTP.start(endpoint.host, endpoint.port) do |http|
        http.request(req)
      end
    elsif params["task_location"].match(/kineticTask\/*$/) != nil
      # Having kineticTask in the url means to use the Task 3 api
      puts "Kinetic Task 3 detected"
      
      path = "/soap/v1/Trigger?wsdl" #Using a SOAP WSDL to make sure the task instance exists
      endpoint = URI(params["task_location"].gsub(/\/+$/,"") + path)

      req = Net::HTTP::Get.new endpoint.to_s
      res = Net::HTTP.start(endpoint.host, endpoint.port) do |http|
        http.request(req)
      end
    else
      raise StandardError, "Cannot find 'kinetic-task' or 'kineticTask' in the task_location info value."
    end


    if res.code.to_s != "200"
      raise StandardError, "Cannot reach the source '#{params['source_name']}' on the task server '#{params['task_location']}'."
    end
    puts "Task Server location and Source successfully found."

    # Turns the params hash in to a json string and then pass it to the knife
    # script
    if Config::CONFIG['target_os'] =~ /mswin/
      # Run the script for windows

      # Split the json string into under 255 char chunks so that it can be
      # fit under the PsExec.exe 255 char limit
      json_string = params.to_json.to_s
      encoded_json = URI.encode(json_string)
      arg_chunks = []
      while !encoded_json.empty?
        chunk = encoded_json.slice!(0...255)
        arg_chunks.push(chunk)
      end
      
      arg_string = ""
      for arg in arg_chunks
        arg_string += "\"#{arg}\" "
      end
      
      # Start the script using PsExec.exe
      puts `cd "#{resources_path}" & PsExec.exe -i -d "ruby" "chefcallback.rb" #{arg_string}`
    else
      # Starting the script using nohup on unix machines.
      `cd #{resources_path}; nohup ./chefcallback.rb #{Shellwords.escape params.to_json.to_s} > /dev/null 2> nohup_#{Time.now.to_i}.err < /dev/null &`
    end

    # Return results
    return <<-RESULTS
    <results>
      <result name="deferral_token">#{@parameters['deferral_token']}</result>
    </results>
    RESULTS
  end
  
  
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
