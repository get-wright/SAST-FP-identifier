require 'json'
require_relative 'helpers'

def process_data(input)
  parsed = JSON.parse(input)
  puts parsed
end

class AuthService
  def authenticate(username, password)
    validate(username)
    query_db(password)
  end

  def self.configure(options)
    options.merge(default: true)
  end
end
