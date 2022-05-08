# Jag vet inte hur jag ska dokumentera dessa
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

# The model part of MVC
module Model
    require 'bcrypt'
    require 'digest'
    require 'time'
    require 'sinatra' # For helpers

    # Returns an sqlite3 database object connected to the applications database
    #
    # @return [SQLite3::Database] connected to the application's database
    def get_db()
        db = SQLite3::Database.new("db/db.db")
        db.results_as_hash = true
        return db
    end

    # Returns the avarage number of stars given in the reviews for a given video
    #
    # @param [Integer] video_id The id of the video
    #
    # @return [Integer] the avarage number of stars
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

            return avg_stars
        end
    end

    # Registers a new user in the database and returns its ID, or an error message if the user could not be added
    #
    # @param [String] username The new user's username
    # @param [String] password The new user's password
    # @param [String] password_confirm The new user's password confirmation. Should be the same as `password`
    #
    # @return [Integer, String] The new user's ID on sucess, an error message otherwise
    def register_user(username, password, password_confirm)
        if password == password_confirm
            password_hash = BCrypt::Password.create(password)
            db = get_db()
            begin
                db.execute("INSERT INTO users (username, password_hash, is_admin, profile_picture, last_login_attempt) VALUES (?, ?, FALSE, '/user_public_data/profile-picture-default.png', (CAST((strftime('%s')) AS INT)))", username, password_hash)
            rescue SQLite3::ConstraintException
                return "Användarnamnet är upptaget"
            end

            return db.execute("SELECT last_insert_rowid()").first["last_insert_rowid()"].to_i
        else
            return "Lösenorden matchade inte"
        end
    end

    # Updates a users time of last attempted login with the current time
    #
    # @param [String] username The username of the user
    #
    # @return [void]
    def register_login_attempt(username)
        db = get_db()
        
        db.execute("UPDATE users
                    SET last_login_attempt = (CAST((strftime('%s')) AS INT))
                    WHERE username = ?", username)
    end

    # Returns a UNIX timestamp of a users last attempted login
    #
    # @param [String] username The username of the user
    #
    # @return [Integer] The UNIX timestamp of the users last attempted login
    def get_last_login_attempt(username)
        db = get_db()
        return db.execute("SELECT last_login_attempt FROM users WHERE username = ?", username).first["last_login_attempt"]
    end

    # Checks a users username and password against the database and returns the user's ID on success.
    # Returns an error message on failure.
    #
    # @param [String] username The provided username of the user
    # @param [String] password The provided password of the user
    #
    # @return [Integer, String] The ID of the user on success. An error message on failure
    def login_user(username, password)
        db = get_db()

        result = db.execute("SELECT * FROM users WHERE username = ?", username).first
        if result
            pw_hash = result["password_hash"]
        else
            return "Användarnamnet existerar inte"
        end

        last_login_attempt = get_last_login_attempt(username)

        if Time.now.to_i - last_login_attempt < 30
            return "Försök igen om #{30 - (Time.now.to_i - last_login_attempt)} sekunder"
        end

        register_login_attempt(username)

        if BCrypt::Password.new(pw_hash) == password
            return result["id"]
        else
            return "Fel lösenord"
        end
    end

    # Returns a hash with the neccesary data to display a user's profile page
    #
    # @param [Integer] user_id The ID of the user whos profile page should be shown
    #
    # @return [Hash]
    #   * :user_data [Hash]
    #     * "id" [Integer] The ID of the user
    #     * "username" [String] The username of the user
    #     * "is_admin" [Integer] 1 if the user is an administrator, 0 otherwise
    #     * "profile_picture" [String] Path to the user's profile picture
    #   * :reviews [Array] Array of hashes with data about all the reviews a user has published
    #     * "username" [String] The username of the user
    #     * "profile_picture" [String] Path to the user's profile picture
    #     * "stars" [Integer} ]The number of stars in the review
    #     * "text" [String] The review content
    #     * "video_id" [Integer] The ID of the video that the review belongs to
    #     * "video_title" [String] The title of the video that the review belongs to
    def get_profile_page_locals(user_id)
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

        print "Reviews: #{reviews.first}\n"
        return {user_data:result, reviews:reviews}
    end

    # Returns a hash with the neccesary data to display a user's profile edit page
    #
    # @param [Integer] user_id The ID of the user whos profile edit page should be shown
    #
    # @return [Hash]
    #   * :user_data [Hash]
    #     * "id" [Integer] The ID of the user
    #     * "username" [String] The username of the user
    #     * "profile_picture" [String] Path to the user's profile picture
    def get_profile_edit_locals(user_id)
        db = get_db()
        result = db.execute("SELECT id, username, profile_picture
                             FROM users
                             WHERE id = ?", params['id']).first
        return {user_data: result}
    end

    # Updates a user's profile. Returns an error message on failure
    #
    # @param [Hash] params Form data
    # @option params [String] new_username, The new username of the user
    # @option params [String] curr_password, The current password of the user
    # @option params [String] new_password, The new password of the user
    # @option params [String] confirm_new_password, The confirmed new password of the user. Should be the same as `new_password`
    # @option params [String] confirm_new_password, The confirmed new password of the user. Should be the same as `new_password`
    # @option params [Hash] new_profile_picture, A hash containing data about the uploaded new profile picture of the user
    #
    # @return [void, String] An error message on failure, or nothing on success
    def update_user(params)
        update_username = false
        update_password = false
        update_pfp = false

        db = get_db()

        user_id = params["id"].to_i

        # TODO: Check for duplicates / handle sql exceptions
        new_username = params["new_username"]
        unless new_username.empty?
            res = db.execute("SELECT id FROM users WHERE username = ?", new_username).first
            if res != nil
                return "Användarnamnet är upptaget"
            end

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
                    return "Nya lösenord matchade inte"
                end

                update_password = true
            end
        else
            unless curr_password.empty?() || new_password.empty?() || new_password_confirm.empty?()
                result = db.execute("SELECT password_hash FROM users WHERE id = ?", user_id).first

                pw_hash = result["password_hash"]
                unless BCrypt::Password.new(pw_hash) == curr_password
                    return "Felaktigt nuvarande lösenord"
                end

                unless new_password == new_password_confirm
                    return "Nya lösenord matchade inte"
                end

                update_password = true
            end
        end

        pfp_data = params["new_profile_picture"]
        if pfp_data
            filetype = pfp_data["type"]

            unless filetype == "image/png" || filetype == "image/jpeg"
                return "Only png and jpeg images are supported"
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
    end

    # Delete a user and all its reviews
    #
    # @param [Integer] user_id The ID of the user
    #
    # @return [void]
    def delete_user_and_data(user_id)
        db = get_db()
        db.execute("DELETE FROM users WHERE id = ?", user_id)
        db.execute("DELETE FROM video_reviews WHERE user_id = ?", user_id)
    end

    # Get all the neccesary data to display the admin page
    #
    # @return [Hash]
    #   * :usernames [Array] Array of hashes containing user information
    #     * "id" [Integer] The id of a user
    #     * "username" [String] The username of a user
    #
    # @return [void]
    def get_admin_locals()
        db = get_db()
        result = db.execute("SELECT id, username FROM users")
        return {usernames:result}
    end

    # Get all the neccesary data to display the videos page
    #
    # @param [String] order The order to display the videos. One of "new", "old", "stars"
    #
    # @return [Hash]
    #   * :videos [Array] Array of hashes containing information about the videos
    #     * "id" [Integer] The ID of a video
    #     * "title" [String] The title of a video
    #     * "upload_date" [Integer] A UNIX timestamp of when a video was uploaded
    def get_video_locals(order)
        db = get_db()

        # Possible are "new", "old", "stars"
        if order.nil?()
            order = "new"
        end

        # Add the avarage star rating to each video
        res = db.execute("SELECT id, title, upload_date FROM videos")
        res.each do |hash|
            hash.store("stars", get_avarage_star_rating(hash["id"]))
        end

        print "res: #{res}\n"

        case order
        when "new"
            res.sort_by! {|hash| hash["upload_date"]}
        when "old"
            res.sort_by! {|hash| hash["upload_date"]}
            res.reverse!()
        when "stars"
            res.sort_by! {|hash| hash["stars"]}
            res.reverse!()
        end

        return {videos:res}
    end

    # Get the neccesary data to display the video upload page
    #
    # @return [Hash]
    #   * genres [Array] Array of hashes containg information about a genre
    #     * "id" [Integer] The id of a genre
    #     * "genre" [String] String describing the genre
    def get_new_video_locals()
        db = get_db()
        res = db.execute("SELECT * FROM genres")
        return {genres:res}
    end

    # Upload a video to the database and return its ID on success. Returns an error message on failure.
    #
    # @param [String] video_title The title of the new video
    # @param [String] video_desc The description of the the video
    # @param [String] video_src Path to the video file
    #
    # @return [Integer, String] The ID of the new video on sucess, or an error message on failure.
    def upload_video(video_title, video_desc, video_src)
        db = get_db()

        if video_desc.empty?()
            video_desc = "Videon saknar beskrivning"
        end

        unless video_title.empty?() || video_src.empty?()
            filetype = video_src["type"]

            unless filetype == "video/mp4"
                return "Endast mp4 formatet stöds för videor"
            end

            video_ext = filetype.split('/')[-1]
            tmpfile_path = video_src["tempfile"]

            video_hash = Digest::SHA256.file(tmpfile_path).hexdigest
     
            path = "./public/videos/#{video_hash}.#{video_ext}"
            path_for_db = "/videos/#{video_hash}.#{video_ext}"
            
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

            return video_id
        else
            return "You must supply a title and a video"
        end
    end

    # Get the data to display the page of a video
    #
    # @param [Integer] video_id The ID of the video
    #
    # @return [Hash]
    #   * :video_data [Array] Array of hashes containing information about the video
    #     * "id" [Integer] The ID of the video
    #     * "title" [String] The title of the video
    #     * "description" [String] The description of the video
    #     * "upload_date" [Integer] The video's upload date as a UNIX timestamp
    #     * "video_src" [String] Path to the video
    #     * "genre" [String] One of the video's genres
    #   * :video_reviews [Array] Array of hashes containing information about the reviews of the video
    #     * "uid" [Integer] The ID of the user who wrote the review
    #     * "username" [String] The username of the user who wrote the review
    #     * "profile_picture" [String] Path to the profile picture of the user who wrote the review
    #     * "rid" [Integer] The ID of the review
    #     * "stars" [Integer] The number of stars in the review
    #     * "text" [String] The text of the review
    def get_video_show_locals(video_id)
        db = get_db()

        # Each index in the array has a different genre
        res = db.execute("SELECT videos.id, videos.title, videos.description, videos.upload_date, videos.video_src, genres.genre
            FROM ((video_genre_relation
                INNER JOIN videos ON videos.id = video_genre_relation.video_id)
                INNER JOIN genres ON genres.id = video_genre_relation.genre_id)
            WHERE video_id = ?", params["id"])

        reviews = db.execute("SELECT users.id AS uid, users.username, users.profile_picture,
                                     video_reviews.id AS rid, video_reviews.stars, video_reviews.text
                              FROM (video_reviews
                                  INNER JOIN users ON users.id = video_reviews.user_id)
                              WHERE video_reviews.video_id = ?", params["id"])

        return {video_data:res, video_reviews:reviews}
    end

    # Add a review to a video
    #
    # @param [Integer] user_id The id of the user who wrote the review
    # @param [Integer] video_id The id of the video that was reviewed
    # @param [Integer] stars The number of stars in the review
    # @param [String] review_text The text of the review
    #
    # @return [void, String] Nil on success, or an error message on failure
    def add_video_review(user_id, video_id, stars, review_text)
        db = get_db()

        test = db.execute("SELECT * FROM videos WHERE id = ?", video_id).first
        if test == nil
            return "Ogiltigt video-id. Säg till en administratör (mig) om du inte orsakade detta med flit."
        end
        if stars < 1 || stars > 5
            return "För många eller för få stjärnor. Sluta inspektera element."
        end
        if review_text.empty?()
            return "Du måste skriva någonting i din recension."
        end

        db.execute("INSERT INTO video_reviews (user_id, video_id, stars, text)
                    VALUES (?, ?, ?, ?)", user_id, video_id, stars, review_text)
    end

    # Check if a review with a certain ID exists
    #
    # @param [Integer] review_id The ID of the review to check if it exists
    #
    # @return [TrueClass, FalseClass] True if the review exists, false otherwise
    def review_exists?(review_id)
        db = get_db()

        test = db.execute("SELECT * FROM video_reviews WHERE id = ?", params["id"]).first
        if test == nil
            return false 
        end
        return true
    end

    # Get the ID of the user who wrote a certain review
    #
    # @param [Integer] review_id The ID of the review to fetch the user ID from
    #
    # @return [Integer] The ID of the user who wrote the review
    def get_review_user_id(review_id)
        db = get_db()
        return db.execute("SELECT user_id FROM video_reviews WHERE id = ?", params["id"]).first["user_id"]
    end

    # Get the ID of the video that was reviewed in a video review
    #
    # @param [Integer] review_id The ID of the review to fetch the video ID from
    #
    # @return [Integer] The ID of the video that was reviewed
    def get_review_video_id(review_id)
        db = get_db()
        return db.execute("SELECT video_id FROM video_reviews WHERE id = ?", params["id"]).first["video_id"]
    end

    # Update a video review with new content
    #
    # @param [Integer] review_id The ID of the review that is to be updated
    # @param [Integer] stars The new number of stars to update to
    # @param [String] review_text The new text of the review
    #
    # @return [void]
    def update_video_review(review_id, stars, review_text)
        db = get_db()

        if stars < 1 || stars > 5
            return "För många eller för få stjärnor. Sluta inspektera element."
        end
        if review_text.empty?()
            return "Du måste skriva någonting i din recension."
        end

        db.execute("UPDATE video_reviews
                    SET stars = ?, text = ?
                    WHERE id = ?", stars, review_text, review_id)
    end
end
