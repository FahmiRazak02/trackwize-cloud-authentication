CREATE DATABASE IF NOT EXISTS trackwize_db;
USE trackwize_db;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    contact_number VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(255) NOT NULL,
    created_by bigint NOT NULL DEFAULT '0',
    created_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by bigint DEFAULT NULL,
    updated_date timestamp NULL DEFAULT CURRENT_TIMESTAMP
    );

INSERT INTO users (email, password, contact_number, name, status, created_by)
VALUES
('fahmirazak0201@gmail.com', '$2a$12$Hb/G4rOnWl15Q1opGT3i8eszCWOT4DGnyOOw4fApM6uYuHYfmFbia', '0145000973', 'Fahmi Razak', 'ACTIVE', 0),
('abukasim93@gmail.com', '$2a$12$Hb/G4rOnWl15Q1opGT3i8eszCWOT4DGnyOOw4fApM6uYuHYfmFbia', '0145000972', 'Abu Kassim', 'ACTIVE', 0);

z