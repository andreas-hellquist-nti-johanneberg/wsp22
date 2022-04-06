require 'sqlite3'

db = SQLite3::Database.new("../db/db.db")
db.results_as_hash = true

while true
  print "New genre: "
  genre = gets.chomp

  db.execute("INSERT INTO genres (genre) VALUES (?)", genre)

  print ("Add one more? (y/n): ")
  unless gets.chomp == 'y'
    break
  end
end
