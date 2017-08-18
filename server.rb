# server.rb
require 'sinatra'
require "sinatra/namespace"
require 'mongoid'
require 'jwt'
require 'openssl'
require 'jwt'
require 'json'
require 'sinatra/cross_origin'

set :bind, '0.0.0.0'

configure do
  enable :cross_origin
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
end

# routes...

options "*" do
  response.headers["Allow"] = "GET, POST, OPTIONS"
  response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, X-User-Email, X-Auth-Token"
  response.headers["Access-Control-Allow-Origin"] = "*"
  200
end


signing_key_path = File.expand_path("../app.rsa", __FILE__)
verify_key_path = File.expand_path("../app.rsa.pub", __FILE__)

signing_key = ""
verify_key = ""

set :public_folder, '/home/lcom75/Desktop/booklist-master/public'


File.open(signing_key_path) do |file|
  signing_key = OpenSSL::PKey.read(file)
end

File.open(verify_key_path) do |file|
  verify_key = OpenSSL::PKey.read(file)
end

set :signing_key, signing_key
set :verify_key, verify_key


# DB Setup
Mongoid.load! "mongoid.config"

# Models
class User
  include Mongoid::Document

  field :fname, type: String
  field :lname, type: String
  field :username, type: String
  field :password, type: String

  validates :fname, presence: true
  validates :lname, presence: true
  validates :username, presence: true
  validates :password, presence: true

  index({fname: 'text'})
  index({lname: 'text'})
  index({username: 'text'})

  scope :username, -> (username) { where(username: username) }
  scope :password, -> (password) { where(password: password) }
end


class UserRuns
  include Mongoid::Document

  field :userId, type: BSON::ObjectId
  field :distance, type: Float
  field :time, type: Integer
  field :date, type: Date

  validates :userId, presence: true
  validates :distance, presence: true
  validates :time, presence: true
  validates :date, presence: true

  scope :userId, -> (userId) { where(userId: userId) }
  scope :date, -> (date) { where(date: date) }
end

# Serializers
class UserSerializer

  def initialize(user)
    @user = user
  end

  def as_json(*)
    data = {
        id: @user.id.to_s,
        fname: @user.fname,
        lname: @user.lname,
        username: @user.username,
        password: @user.password
    }
    data[:errors] = @user.errors if @user.errors.any?
    data
  end

end

class UserRunSerializer

  def initialize(userRun)
    @userRun = userRun
  end

  def as_json(*)
    data = {
        id: @userRun.id.to_s,
        userId: @userRun.userId,
        distance: @userRun.distance,
        time: @userRun.time,
        date: @userRun.date
    }
    data[:errors] = @userRun.errors if @userRun.errors.any?
    data
  end

end

class ImageSerializer

  def initialize(image)
    @image = image
  end

  def as_json(*)
    data = {
        id: @image.id.to_s,
        image: @image.imagename,

    }
    data[:errors] = @image.errors if @image.errors.any?
    data
  end

end

class ImageList
  include Mongoid::Document

  field :imagename, type: String

  validates :imagename, presence: true

end


# Endpoints
get '/' do
  'Welcome to API!'
end

namespace '/api/v1' do

  before do
    content_type 'application/json'
  end

  helpers do
    def base_url
      @base_url ||= "#{request.env['rack.url_scheme']}://#{request.env['HTTP_HOST']}"
    end

    def json_params
      begin
        JSON.parse(request.body.read)
      rescue
        halt 400, {message: 'Invalid JSON'}.to_json
      end
    end

    def user
      @user ||= User.where(id: params[:id]).first
    end

    def halt_if_not_found!
      halt(404, {message: 'User Not Found'}.to_json) unless user
    end

    def userRun
      @userRun ||= UserRuns.where(id: params[:id]).first
    end

    def halt_if_not_found_for_userRun!
      halt(404, {message: 'UserRun Not Found'}.to_json) unless userRun
    end

    def serialize(user)
      UserSerializer.new(user).to_json
    end

    def serializeRun(userRun)
      UserRunSerializer.new(userRun).to_json
    end

    def protected!
      return authorized?
    end

    def extract_token
      # check for the access_token header

      token = request.env["access_token"]

      if token
        return token
      end

      # or the form parameter _access_token
      token = request["access_token"]

      if token
        return token
      end

      # or check the session for the access_token
      token = session["access_token"]

      if token
        return token
      end

      return nil
    end

    def authorized?
      @token = extract_token
      puts (@token)
      begin
        if @token.nil?
          puts "Access token not found"
          return false
        end
        payload, header = JWT.decode(@token, settings.verify_key, true)

        @exp = header["exp"]


        if @exp.nil?
          puts "Access token doesn't have exp set"
          return false
        end

        @exp = Time.at(@exp.to_i)

        if Time.now > @exp
          puts "Access token expired"
          return false
        else
          return true
        end

        @user_id = payload["user_id"]

      rescue JWT::DecodeError => e
        return false
      end
    end

  end

  get '/users' do
   @isAuthorized = protected!
   if @isAuthorized
     users = User.all

     [:fname, :lname, :username, :password].each do |filter|
       users = users.send(filter, params[filter]) if params[filter]
     end

     users.map { |user| UserSerializer.new(user) }.to_json
   else
     status 401
     {:message => "Unauthorized"}.to_json
   end

  end

  get '/login' do
    users = User.all

    [:fname, :lname, :username, :password].each do |filter|
      users = users.send(filter, params[filter]) if params[filter]
    end

    if (users.length === 1)
      headers = {
          exp: Time.now.to_i + 2000 #expire in 20 seconds
      }

      @token = JWT.encode({user_id: 123456}, settings.signing_key, "RS256", headers)
      @token = JWT.encode({user_id: users[0].id}, settings.signing_key, "RS256", headers)
      content_type :json
      {:token => @token, :userId => users[0].id}.to_json
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end


    #serialize(users[0])
    #users.map { |user| UserSerializer.new(user) }.to_json
  end

  get '/users/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      halt_if_not_found!
      serialize(user)
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end
  end

  get '/checkusername' do

    @userfound = User.where(username: params[:username]).first
    puts @userfound
    if (@userfound != nil)
      status 200
      {:message => "Username already exist"}.to_json
    else
      status 200
      {:message => "Username available"}.to_json
    end
  end

  post '/users' do

    user = User.new(json_params)
    halt 422, serialize(user) unless user.save
    response.headers['Location'] = "#{base_url}/api/v1/users/#{user.id}"
    status 201

  end

  patch '/users/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      halt_if_not_found!
      halt 422, serialize(user) unless user.update_attributes(json_params)
      serialize(user)
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end

  end

  delete '/users/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      user.destroy if user
      status 204
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end

  end

  post '/userRuns' do
    userrun = UserRuns.new(json_params)
    halt 422, serialize(userrun) unless userrun.save
    #response.headers['Location'] = "#{base_url}/api/v1/users/#{user.id}"
    status 201
  end

  get '/userRuns' do
    @isAuthorized = protected!
    if @isAuthorized
      userRuns = UserRuns.all
      userRuns.map { |userRuns| UserRunSerializer.new(userRuns) }.to_json
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end
  end

  get '/userRuns/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      halt_if_not_found_for_userRun!
      serializeRun(userRun)
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end
  end

  patch '/userRuns/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      halt_if_not_found_for_userRun!
      halt 422, serialize(userRun) unless userRun.update_attributes(json_params)
      serializeRun(userRun)
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end
  end

  delete '/userRuns/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      users = UserRuns.all

      [:fname, :lname, :username, :password].each do |filter|
        users = users.send(filter, params[filter]) if params[filter]
      end

      users.map { |user| UserRunSerializer.new(user) }.to_json
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end

    userRun.destroy if userRun
    status 204
  end

  get '/user/userRuns/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      userRuns = UserRuns.where(userId: id)
      userRuns.map { |userRuns| UserRunSerializer.new(userRuns) }.to_json
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end
  end

  get '/getWeeklyReport/:id' do |id|
    @isAuthorized = protected!
    if @isAuthorized
      userRuns = UserRuns.where(userId: id).where(:date.gte => params[:fromDate]).where(:date.lte => params[:endDate])
      $i = 0
      $totalSpeed = 0
      $totalDistance = 0
      $totalTime = 0
      while $i < userRuns.length do
        puts("Inside the loop i = #$i" )
        puts (userRuns[$i].distance)
        $totalDistance += userRuns[$i].distance
        $totalTime += userRuns[$i].time
        $speed = userRuns[$i].distance / userRuns[$i].time
        $totalSpeed += $speed
        $i +=1
      end
      status 200
      {:totalDistance => $totalDistance , :avgTime => $totalTime/userRuns.length  , :avgSpeed => $totalSpeed/userRuns.length }.to_json

    else
      status 401
      {:message => "Unauthorized"}.to_json
    end

  end

  post "/upload" do
    File.open('public/' + params['myfile'][:filename], "w") do |f|
      f.write(params['myfile'][:tempfile].read)
    end
    image =  ImageList.create(:imagename => params['myfile'][:filename] );
    image.save
    return {:message => "Image Uploaded Successfully" }.to_json
  end

  get '/listImage' do
    @isAuthorized = protected!
    if @isAuthorized
      images = ImageList.all
      images.map { |image| ImageSerializer.new(image) }.to_json
    else
      status 401
      {:message => "Unauthorized"}.to_json
    end

  end

end
