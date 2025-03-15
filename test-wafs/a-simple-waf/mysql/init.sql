CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

INSERT INTO users (username, password) VALUES ('admin', '4d2e58c872d529fba1d14ba0949b644d');
INSERT INTO users (username, password) VALUES ('user', 'df482a0138a51b3cb6ec2fb46de082c8');
INSERT INTO users (username, password) VALUES ('guest', '30041269352280e58c77dde5cc29550a');
