require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require 'digest'

enable :sessions

def get_db()
    db = SQLite3::Database.new("db/db.db")
    db.results_as_hash = true
    return db
end

def get_avarage_star_rating(video_id)
    db = get_db()
    res = db.execute("SELECT stars FROM video_reviews WHERE video_id = ?", video_id)
    if res.empty?()
        return 0
    else
        total_stars = 0
        for i in res do
            total_stars += i["stars"]
        end
        avg_stars = total_stars.to_f / res.length

        print("JKJKFJKFJKFJKFJKFJKJ")

        return avg_stars
    end
end

# def filetype_from_file_param(file)
#     p "DATA: #{pfp_data}"
#     content_type_header = pfp_data["head"].chomp.lines[-1]
#     p "CONTENT TYPE: #{content_type}"
#     filetype = content_type_header.split(' ')[-1]
# 
#     return filetype
# end

helpers do
    def user_is_logged_in
        return session.key?(:user_id)
    end

    def user_is_admin()
        if not user_is_logged_in
            return false
        end

        db = get_db()
        result = db.execute("SELECT is_admin FROM users WHERE id = ?", session[:user_id]).first
        return (not result["is_admin"].zero?)
    end

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
post '/users' do
    username = params["username"]
    password = params["password"]
    password_confirm = params["password_confirm"]

    if password == password_confirm
        # Lägg till användare
        password_hash = BCrypt::Password.create(password)
        db = get_db()
        begin
            db.execute("INSERT INTO users (username, password_hash, is_admin, profile_picture) VALUES (?, ?, FALSE, '/user_public_data/profile-picture-default.png')", username, password_hash)
        rescue SQLite3::ConstraintException
            halt "Användarnamnet är upptaget"
        end

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
get '/users/login' do
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

get '/users/profile/:id' do
    db = get_db()
    result = db.execute("SELECT id, username, is_admin, profile_picture
                         FROM users
                         WHERE id = ?", params['id']).first

    reviews = db.execute("SELECT users.username, users.profile_picture,
                                video_reviews.stars, video_reviews.text, video_reviews.video_id,
                                videos.title AS video_title
                         FROM ((users
                             INNER JOIN video_reviews ON users.id = video_reviews.user_id)
                             INNER JOIN videos ON videos.id = video_reviews.video_id)
                         WHERE users.id = ?", params['id'])

    unless result
        return "User does not exist"
    end

    slim(:'users/profile', locals:{user_data:result, reviews:reviews})
end

get '/users/:id/edit' do
    if (not user_is_logged_in)
        halt "Logga in först"
    end

    unless session[:user_id] == params["id"].to_i || (user_is_admin)
        halt 403, "Forbidden osv"
    end

    db = get_db()
    result = db.execute("SELECT id, username, profile_picture
                         FROM users
                         WHERE id = ?", params['id']).first

    unless result
        return "User does not exist"
    end

    slim(:'users/edit', locals:{user_data:result})
end

post '/users/:id/update' do
    if (not user_is_logged_in)
        halt "Logga in först"
    end

    unless session[:user_id] == params["id"].to_i || (user_is_admin)
        halt 403, "Forbidden osv"
    end

    update_username = false
    update_password = false
    update_pfp = false

    db = get_db()

    user_id = params["id"].to_i

    # TODO: Check for duplicates / handle sql exceptions
    new_username = params["new_username"]
    unless new_username.empty?
        update_username = true
    end

    curr_password = params["curr_password"]
    new_password = params["new_password"]
    new_password_confirm = params["confirm_new_password"]
    # Admin can just change a users password without needing to know the current
    # password
    if user_is_admin
        unless new_password.empty?() || new_password_confirm.empty?()
            unless new_password == new_password_confirm
                halt "Nya lösenord matchade inte"
            end

            update_password = true
        end
    else
        unless curr_password.empty?() || new_password.empty?() || new_password_confirm.empty?()
            result = db.execute("SELECT password_hash FROM users WHERE id = ?", user_id).first

            pw_hash = result["password_hash"]
            unless BCrypt::Password.new(pw_hash) == curr_password
                halt "Felaktigt nuvarande lösenord"
            end

            unless new_password == new_password_confirm
                halt "Nya lösenord matchade inte"
            end

            update_password = true
        end
    end

    pfp_data = params["new_profile_picture"]
    if pfp_data
        filetype = pfp_data["type"]

        unless filetype == "image/png" || filetype == "image/jpeg"
            halt "Only png and jpeg images are supported"
        end

        update_pfp = true
    end

    # We do all the updating in the end to avoid partly updating things in the case
    # of errors
    if update_username
        db.execute("UPDATE users
                    SET username = ?
                    WHERE id = ?", new_username, user_id)
    end

    if update_password
        new_pw_hash = BCrypt::Password.create(new_password)
        db.execute("UPDATE users
                    SET password_hash = ?
                    WHERE id = ?", new_pw_hash, user_id)
    end

    if update_pfp
        pfp_ext = filetype.split('/')[-1]
        tmpfile_path = pfp_data["tempfile"]

        pfp_hash = Digest::SHA256.file(tmpfile_path).hexdigest
 
        path = "./public/user_public_data/#{pfp_hash}.#{pfp_ext}"
        path_for_db = "/user_public_data/#{pfp_hash}.#{pfp_ext}"
        
        #Lägg till path i databas
        db.execute("UPDATE users
                    SET profile_picture = ?
                    WHERE id = ?", path_for_db, user_id)
        
        #Spara bilden (skriv innehållet i tempfile till destinationen path)
        File.write(path, File.read(tmpfile_path))
    end
 
    redirect "/users/profile/#{user_id}"
end

post('/users/:id/delete') do
    unless (user_is_admin)
        halt 403, "No"
    end

    user_id = params["id"]

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", user_id)
    db.execute("DELETE FROM video_reviews WHERE user_id = ?", user_id)

    redirect '/'
end

before '/admin' do
    unless user_is_admin
        halt 403, "Don't"
    end
end

get('/admin') do
    db = get_db()
    result = db.execute("SELECT id, username FROM users")
    slim(:admin, locals:{usernames:result})
end

get '/videos' do
    db = get_db()
    # Possible are "new", "old", "stars"
    order = params["video_order"]
    if order.nil?()
        order = "new"
    end

    # Add the avarage star rating to each video
    res = db.execute("SELECT id, title, upload_date FROM videos")
    res.each do |hash|
        hash.store("stars", get_avarage_star_rating(hash["id"]))
    end
    puts res

    puts "NOW IM HEREEERER"
    case order
    when "new"
        res.sort! {|hash| hash["upload_date"]}
    when "old"
        res.sort! {|hash| hash["upload_date"]}
        res.reverse!()
    when "stars"
        res.sort! {|hash| hash["stars"]}
    end

    slim(:'videos/index', locals:{videos:res})
end

before '/videos/new' do
    unless user_is_admin
        halt 403, "Don't"
    end
end

get('/videos/new') do
    db = get_db()
    res = db.execute("SELECT * FROM genres")
    slim(:'videos/new', locals:{genres:res})
end

# {"filename"=>"2022-03-17_20-24-57.mp4", "type"=>"video/mp4", "name"=>"video_src", "tempfile"=>#<Tempfile:/tmp/RackMultipart20220330-2616-1o62fw8.mp4>, "head"=>"Content-Disposition: form-data; name=\"video_src\"; filename=\"2022-03-17_20-24-57.mp4\"\r\nContent-Type: video/mp4\r\n"}
post('/videos') do
    unless (user_is_admin)
        halt 403, "You are not admin"
    end

    db = get_db()

    video_title = params["video_title"]
    video_desc = params["description"]
    video_src = params["video_src"]

    if video_desc.empty?()
        video_desc = "Videon saknar beskrivning"
    end

    unless video_title.empty?() || video_src.empty?()
        filetype = video_src["type"]

        unless filetype == "video/mp4"
            halt "Endast mp4 formatet stöds för videor"
        end

        video_ext = filetype.split('/')[-1]
        tmpfile_path = video_src["tempfile"]

        video_hash = Digest::SHA256.file(tmpfile_path).hexdigest
 
        path = "./public/videos/#{video_hash}.#{video_ext}"
        path_for_db = "/videos/#{video_hash}.#{video_ext}"
        
        #Lägg till path i databas
        db.execute("INSERT INTO videos
                     (title, description, video_src, upload_date)
                     VALUES (?, ?, ?, (CAST((strftime('%s')) AS INT)))", video_title, video_desc,
                                                        path_for_db)
        video_id = db.execute("SELECT last_insert_rowid()").first["last_insert_rowid()"]
        
        #Spara bilden (skriv innehållet i tempfile till destinationen path)
        File.write(path, File.read(tmpfile_path))

        # Add genres to the relation table
        genre_ids = db.execute("SELECT id FROM genres").map {|genre| genre["id"]}
        for genre_id in genre_ids do
            if params["genre_#{genre_id}"] == 'on'
                db.execute("INSERT INTO video_genre_relation (video_id, genre_id)
                            VALUES (?, ?)", video_id, genre_id)
            end
        end
    else
        halt "You must supply a title and a video"
    end

    redirect "/videos/#{video_id}"
end

get('/videos/:id') do
    # Video showwy stuff
    db = get_db()
    # Also get the reviews here
    # Each index in the array has a different genre
    res = db.execute("SELECT videos.id, videos.title, videos.description, videos.upload_date, videos.video_src, genres.genre
        FROM ((video_genre_relation
	    INNER JOIN videos ON videos.id = video_genre_relation.video_id)
	    INNER JOIN genres ON genres.id = video_genre_relation.genre_id)
        WHERE video_id = ?", params["id"])

    p res

    reviews = db.execute("SELECT users.id AS uid, users.username, users.profile_picture,
                                 video_reviews.id AS rid, video_reviews.stars, video_reviews.text
                          FROM (video_reviews
                              INNER JOIN users ON users.id = video_reviews.user_id)
                          WHERE video_reviews.video_id = ?", params["id"])
    p reviews

    slim(:'videos/show', locals:{video_data:res, video_reviews:reviews})
end

post('/video-reviews') do
    if user_is_logged_in()
        db = get_db()

        user_id = session[:user_id]
        video_id = params["video-id"].to_i
        stars = params["num-stars"].to_i
        review_text = params["review-text"]

        test = db.execute("SELECT * FROM videos WHERE id = ?", video_id).first
        if test == nil
            halt "Ogiltigt video-id. Säg till en administratör (mig) om du inte orsakade detta med flit."
        end
        if stars < 1 || stars > 5
            halt "För många eller för få stjärnor. Sluta inspektera element."
        end
        if review_text.empty?()
            halt "Du måste skriva någonting i din recension."
        end

        db.execute("INSERT INTO video_reviews (user_id, video_id, stars, text)
                    VALUES (?, ?, ?, ?)", user_id, video_id, stars, review_text)

        redirect "/videos/#{video_id}"
    else
        halt "Hur hamnade du här?"
    end
end

post('/video-reviews/:id/update') do
    if user_is_logged_in()
        db = get_db()

        res = db.execute("SELECT user_id FROM video_reviews WHERE id = ?", params["id"]).first
        unless session[:user_id] == res["user_id"] || (user_is_admin)
            halt 403, "Nej du får inte redigera någon annans recension"
        end

        stars = params["num-stars"].to_i
        review_text = params["review-text"]

        test = db.execute("SELECT * FROM video_reviews WHERE id = ?", params["id"]).first
        if test == nil
            halt "Ogiltigt recension-id"
        end
        if stars < 1 || stars > 5
            halt "För många eller för få stjärnor. Sluta inspektera element."
        end
        if review_text.empty?()
            halt "Du måste skriva någonting i din recension."
        end

        db.execute("UPDATE video_reviews
                    SET stars = ?, text = ?
                    WHERE id = ?", stars, review_text, params["id"])

        redirect "/videos/#{test["video_id"]}"
    else
        halt "Hur hamnade du här?"
    end
end
