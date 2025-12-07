CREATE TABLE `users` (
	`id` int AUTO_INCREMENT NOT NULL,
	`public_key` varchar(255) NOT NULL,
	`private_key_hash` varchar(255) NOT NULL,
	`iota_id` int NOT NULL,
	`token` varchar(255) NOT NULL,
	`username` varchar(255) NOT NULL,
	`display` varchar(255),
	`avatar` longblob,
	`about` text,
	`status` varchar(255),
	`sub_level` int NOT NULL DEFAULT 0,
	`sub_end` int NOT NULL DEFAULT 0,
	CONSTRAINT `users_id` PRIMARY KEY(`id`)
);
