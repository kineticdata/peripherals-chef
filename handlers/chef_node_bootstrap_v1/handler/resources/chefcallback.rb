#!/usr/bin/env ruby

require 'rubygems'
require 'net/http'
require 'json'
require 'time'
require 'uri'

File.open("bootstrap_run_#{Time.now.to_i}.log",'w') do |f|
    f.puts "Starting the bootstrap progress"

    # Assign the inputted json string to a variable
    json_string_encoded = ARGV.join.to_s 
    json_string = URI.decode(json_string_encoded)

    json = JSON.parse(json_string)

    # Performing the bootstrap of the node in chef
    f.puts `knife bootstrap #{json['server_name']} -x #{json['user_config']} -N "#{json['node_name']}" -r "#{json['recipe']}" -c "#{json['knife_path']}"`

    # Permorming the callback to complete the deferral process for the 
    # chef bootstrap node
    f.puts "Using the deferral token passed to the application, making a call to the task server to continue the deferred node"

    res = nil
    if json["task_location"].match(/kinetic-task\/*$/) != nil # Task 4
        path = "/app/api/v1/complete-deferred-task/#{json["source_name"]}"
        endpoint = URI(json["task_location"].gsub(/\/+$/,"") + path)

        req = Net::HTTP::Post.new(endpoint, initheader = {'Content-Type' =>'application/json'})
        req.body = {'token' => json["deferral_token"]}.to_json
        res = Net::HTTP.start(endpoint.hostname, endpoint.port) do |http|
          http.request(req)
        end
    else # Task 3
        path = "/rest/v1/Trigger/createDeferred"
        endpoint = URI(json["task_location"].gsub(/\/+$/,"") + path)

        req = Net::HTTP::Post.new(endpoint)
        req.set_form_data({"action" => "Complete", "token" => json["deferral_token"]})
        res = Net::HTTP.start(endpoint.hostname, endpoint.port) do |http|
          http.request(req)
        end
    end

    f.puts res.code
    f.puts res.body

    f.puts "Bootstrap and deferred continue complete"
end