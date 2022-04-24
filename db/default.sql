CREATE TABLE users (
    -- If the primary key is an integer it becomes an alias for rowid which
    -- uses unique 64 bit numbers, so autoincrement and not null are not needed
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL,
    profile_picture TEXT NOT NULL
);

CREATE TABLE videos (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    video_src TEXT NOT NULL,
    -- Stored as a unix timestamp
    upload_date INTEGER NOT NULL
);

CREATE TABLE video_reviews (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    video_id INTEGER NOT NULL,
    stars INTEGER NOT NULL,
    text INTEGER NOT NULL
);

-- CREATE TABLE user_video_rating_relation (
--     user_id INTEGER NOT NULL,
--     video_id INTEGER NOT NULL,
--     stars INTEGER NOT NULL
-- );

-- CREATE TABLE video_comments (
--     id INTEGER PRIMARY KEY,
--     video_id INTEGER NOT NULL,
--     user_id INTEGER NOT NULL,
--     content TEXT NOT NULL,
--     upload_date INTEGER NOT NULL
-- );

-- CREATE TABLE blog_comments (
--     id INTEGER PRIMARY KEY,
--     blog_id INTEGER NOT NULL,
--     user_id INTEGER NOT NULL,
--     content TEXT NOT NULL,
--     upload_date INTEGER NOT NULL
-- );
-- 
-- CREATE TABLE blogposts (
--     id INTEGER PRIMARY KEY,
--     content TEXT NOT NULL,
--     upload_date INTEGER NOT NULL
-- );

CREATE TABLE genres (
    id INTEGER PRIMARY KEY,
    genre TEXT NOT NULL UNIQUE
);

-- CREATE TABLE blogpost_genre_relation (
--     blogpost_id INTEGER NOT NULL,
--     genre_id INTEGER NOT NULL
-- );

CREATE TABLE video_genre_relation (
    video_id INTEGER NOT NULL,
    genre_id INTEGER NOT NULL
);
