require 'sqlite3'
require 'bcrypt'

db = SQLite3::Database.new("../db/db.db")
db.results_as_hash = true

print "Name of user: "
username = gets.chomp

id = db.execute("SELECT id FROM users WHERE username = ?", username).first["id"]
unless id
  puts "User does not exist :("
  exit
end

print "New password: "
pw = gets.chomp


new_pw_hash = BCrypt::Password.create(pw)
db.execute("UPDATE users
            SET password_hash = ?
            WHERE id = ?", new_pw_hash, id)

puts "Done :)"
