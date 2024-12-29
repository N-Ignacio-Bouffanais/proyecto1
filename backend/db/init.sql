CREATE DATABASE IF NOT EXISTS ip_analysis;

USE ip_analysis;

CREATE TABLE ip_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    type VARCHAR(10),
    country VARCHAR(100),
    city VARCHAR(100),
    isp VARCHAR(255),
    organization VARCHAR(255),
    is_trusted_isp BOOLEAN,
    is_valid_location BOOLEAN,
    is_known_attacker BOOLEAN,
    is_proxy BOOLEAN,
    is_tor BOOLEAN,
    is_crawler BOOLEAN,
    status ENUM('Confiable', 'Sospechosa', 'Maliciosa'),
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
