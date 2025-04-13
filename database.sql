create table "Users"
(
    "PrimaryKey"         uuid                    not null
        primary key,
    "Username"           varchar(50)             not null,
    "PasswordHash"       bytea                   not null,
    "PasswordSalt"       bytea                   not null,
    "PublicKey"          bytea                   not null,
    "CreatedAt"          timestamp default now() not null,
    "LastLogin"          timestamp               not null,
    "RefreshToken"       text,
    "RefreshTokenExpiry" timestamp
);
