require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require_relative './model.rb'

enable :sessions

include Model

# Display Landing Page
#
get '/' do
    slim :start
end

# Displays a form for registering users
#
get '/users/new' do
    slim :"users/new"
end

# Creates a new user and redirects to its profile page
#
# @param [String] username The username of the new user
# @param [String] password The password of the new user
# @param [String] password_confirm The confirmed password of the new user. Should be the same as `password`
#
# @see Model#register_user
post '/users' do
    username = params["username"]
    password = params["password"]
    password_confirm = params["password_confirm"]

    res = register_user(username, password, password_confirm)

    # Handle error
    case res.class.to_s
    when 'String'
        halt res
    when 'Integer'
        session[:user_id] = res
    end

    redirect "/users/profile/#{session[:user_id]}"
end

# Logs out a user and redirects to '/'
#
post '/users/logout' do
    session.delete(:user_id)
    redirect '/'
end

# Displays a form for logging in users
# Redirects to the users profile page if it is already logged in
#
get '/users/login' do
    # Redirecta om användaren redan är inloggad
    if user_is_logged_in
        redirect "/users/profile/#{session[:user_id]}"
    end

    slim(:"users/login")
end

# Logs in a user and redirects to its profile page
#
# @param [String] username The username of the user
# @param [String] password The password of the user
#
# @see Model#login_user
post '/users/login' do
    username = params["username"]
    password = params["password"]

    res = login_user(username, password)

    # Felhantering
    case res.class.to_s
    when 'String'
        halt res
    when 'Integer'
        session[:user_id] = res
    end

    redirect "/users/profile/#{session[:user_id]}"
end

# Displays a users profile page
#
# @param [Integer] :id the ID of the user
get '/users/profile/:id' do
    view_contents = get_profile_page_locals(params["id"])

    unless view_contents[:user_data]
        halt "User does not exist"
    end

    slim(:'users/profile', locals:view_contents)
end

# Displays a form for editing a user
#
# @param [Integer] :id the ID of the user
get '/users/:id/edit' do
    # Authorization
    if (not user_is_logged_in)
        halt "Logga in först"
    end

    unless session[:user_id] == params["id"].to_i || (user_is_admin)
        halt 403, "Forbidden osv"
    end

    view_contents = get_profile_edit_locals(params["id"])

    # Felhantering
    unless view_contents[:user_data]
        halt "User does not exist"
    end

    slim(:'users/edit', locals:view_contents)
end

# Update a users profile
#
# @param [Integer] :id The ID of the user
# @param [String] new_username The new username of the user
# @param [String] curr_password The current password of the user
# @param [String] new_password The new password of the user
# @param [String] confirm_new_password The confirmed new password of the user. Should be the same as `new_password`
# @param [String] confirm_new_password The confirmed new password of the user. Should be the same as `new_password`
# @param [Hash] new_profile_picture A hash containing data about the uploaded new profile picture of the user
#
# @see Model#update_user
post '/users/:id/update' do
    # Authorization
    if (not user_is_logged_in)
        halt "Logga in först"
    end

    unless session[:user_id] == params["id"].to_i || (user_is_admin)
        halt 403, "Forbidden osv"
    end

    res = update_user(params)
    if res.class == String
        halt res
    end

    redirect "/users/profile/#{params["id"]}"
end

# Delete a user and all its reviews
#
# @param [Integer] :id The ID of the user
#
# @see Model#delete_user_and_data
post('/users/:id/delete') do
    unless (user_is_admin)
        halt 403, "No"
    end

    delete_user_and_data(params["id"])

    redirect '/'
end

# Borde jag dokumentera before?
before '/admin' do
    unless user_is_admin
        halt 403, "Don't"
    end
end

# Displays admin page
#
get('/admin') do
    view_contents = get_admin_locals()
    slim(:admin, locals:view_contents)
end

# Displays page containing links to all videos
#
# @param [String] video_order, The order that the videos are displayed. Allowed values are "new", "old" and "stars"
get '/videos' do
    view_contents = get_video_locals(params["video_order"])
    slim(:'videos/index', locals:view_contents)
end

before '/videos/new' do
    unless user_is_admin
        halt 403, "Don't"
    end
end

# Displays a form for uploading a new video
#
get('/videos/new') do
    view_contents = get_new_video_locals()
    slim(:'videos/new', locals:view_contents)
end

# Uploads a new video and redirects to the new video's page
# 
# @param [String] video_title The title of the new video
# @param [String] description The description of the new video
# @param [Hash] video_src Hash containing data about the uploaded video
#
# @see Model#upload_video
post('/videos') do
    unless (user_is_admin)
        halt 403, "You are not admin"
    end

    res = upload_video(params["video_title"], params["description"], params["video_src"]) 
    if res.class == String
        halt res
    end

    redirect "/videos/#{res}"
end

# Displays page with video and its reviews
#
# @param [Integer] :id The ID of the video
get('/videos/:id') do
    view_contents = get_video_show_locals(params["id"])
    slim(:'videos/show', locals:view_contents)
end

# Add a new video review and redirect to the video's page
#
# @param [String] video-id The ID of the video
# @param [String] num-stars The number of stars in the review
# @param [String] review-text The text of the review
#
# @see Model#add_video_review
post('/video-reviews') do
    if user_is_logged_in()

        user_id = session[:user_id]
        video_id = params["video-id"].to_i
        stars = params["num-stars"].to_i
        review_text = params["review-text"]

        res = add_video_review(user_id, video_id, stars, review_text)

        if res.class == String
            halt res
        end

        redirect "/videos/#{video_id}"
    else
        halt "Hur hamnade du här?"
    end
end

# Update a video review and redirect to to the video's page
#
# @param [Integer] :id The id of the review
# @param [String] num-stars The number of stars in the review
# @param [String] review-text The text of the review
#
# @see Model#update_video_review
post('/video-reviews/:id/update') do
    if user_is_logged_in()
        db = get_db()

        unless review_exists?(params["id"])
            halt "Ogiltigt recension-id"
        end

        unless session[:user_id] == get_review_user_id(params["id"]) || (user_is_admin)
            halt 403, "Nej du får inte redigera någon annans recension"
        end

        stars = params["num-stars"].to_i
        review_text = params["review-text"]

        res = update_video_review(params["id"], stars, review_text)
        if res.class == String
            halt res
        end

        video_id = get_review_video_id(params["id"])

        redirect "/videos/#{video_id}"
    else
        halt "Hur hamnade du här?"
    end
end
