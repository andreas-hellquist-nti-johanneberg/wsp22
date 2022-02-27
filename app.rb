require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'

enable :sessions

def get_db()
    db = SQLite3::Database.new("db/db.db")
    db.results_as_hash = true
    return db
end

helpers do
    def username_from_session_id
        db = get_db()
        p session[:user_id]
        result = db.execute("SELECT username FROM users WHERE id = ?", session[:user_id]).first
        p result
        return result["username"]
    end
end

get '/' do
    slim :start
end

get '/users/new' do
    slim :"users/new"
end

# Add user
# TODO: Two users can't have the same username. Do something about sql exceptions
#       when that occurs
post '/users' do
    username = params["username"]
    password = params["password"]
    password_confirm = params["password_confirm"]

    if password == password_confirm
        # Lägg till användare
        password_hash = BCrypt::Password.create(password)
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash, is_admin, profile_picture) VALUES (?, ?, FALSE, '/user_public_data/profile-picture-default.png')", username, password_hash)

        session[:user_id] = db.execute("SELECT id FROM users WHERE username = ?", username).first["id"]
        redirect '/'
    else
        # TODO: Snygg felhantering
        "Lösenorden matchade inte"
    end
end

post '/users/logout' do
    session.delete(:user_id)
    redirect '/'
end

# TODO: Redirecta om redan inloggad
get '/users/showlogin' do
    slim(:"users/login")
end

post '/users/login' do
    username = params["username"]
    password = params["password"]

    db = get_db()

    result = db.execute("SELECT * FROM users WHERE username = ?", username).first
    if result
        pw_hash = result["password_hash"]
    else
        return "Användarnamnet existerar inte"
    end

    if BCrypt::Password.new(pw_hash) == password
        # It works
        session[:user_id] = result["id"]
        redirect '/'
    else
        # Wrong password
        "Fel lösenord"
    end
end
