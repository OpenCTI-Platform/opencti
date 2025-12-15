CREATE TABLE `entity` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`entity_type` varchar(50) NOT NULL,
	`parent_types` json NOT NULL,
	`representative_main` varchar(256) NOT NULL,
	`creator_id` bigint,
	`target_id` bigint NOT NULL,
	`target_table` varchar(50) NOT NULL,
	`created_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`modified_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `entity_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `identifier` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`identifier` varchar(255),
	`type` varchar(50) NOT NULL,
	`creator_id` bigint,
	`target_id` bigint NOT NULL,
	`target_table` varchar(50) NOT NULL,
	`created_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`modified_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `identifier_id` PRIMARY KEY(`id`),
	CONSTRAINT `identifier_identifier_unique` UNIQUE(`identifier`)
);
--> statement-breakpoint
CREATE TABLE `intrusion-set` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`first_seen` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`last_seen` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `intrusion-set_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `malware` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`description` text,
	`malware_types` json,
	`implementation_languages` json,
	`architecture_execution_envs` json,
	`capabilities` json,
	`is_family` boolean DEFAULT false,
	`first_seen` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`last_seen` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `malware_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `relationship` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`relationship_type` varchar(50) NOT NULL,
	`parent_types` json NOT NULL,
	`creator_id` bigint,
	`from_id` bigint NOT NULL,
	`from_table` varchar(50) NOT NULL,
	`to_id` bigint NOT NULL,
	`to_table` varchar(50) NOT NULL,
	`created_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`modified_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `relationship_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `stub` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`order` int NOT NULL,
	`color` varchar(255) NOT NULL,
	`category` varchar(255) NOT NULL,
	CONSTRAINT `stub_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `user` (
	`id` bigint AUTO_INCREMENT NOT NULL,
	`user_email` varchar(256),
	`password` text,
	`name` varchar(256),
	`description` text,
	`firstname` varchar(256),
	`lastname` varchar(256),
	`created_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	`modified_at` timestamp(6) DEFAULT CURRENT_TIMESTAMP(6),
	CONSTRAINT `user_id` PRIMARY KEY(`id`),
	CONSTRAINT `user_user_email_unique` UNIQUE(`user_email`)
);
--> statement-breakpoint
ALTER TABLE `entity` ADD CONSTRAINT `entity_creator_id_user_id_fk` FOREIGN KEY (`creator_id`) REFERENCES `user`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identifier` ADD CONSTRAINT `identifier_creator_id_user_id_fk` FOREIGN KEY (`creator_id`) REFERENCES `user`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `relationship` ADD CONSTRAINT `relationship_creator_id_user_id_fk` FOREIGN KEY (`creator_id`) REFERENCES `user`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `idx_parent_types` ON `entity` ((CAST(`parent_types` AS CHAR(32) ARRAY)));--> statement-breakpoint
CREATE INDEX `idx_ident_reverse` ON `identifier` (`id`);--> statement-breakpoint
CREATE INDEX `idx_intrusion_set_name` ON `intrusion-set` (`name`);--> statement-breakpoint
CREATE INDEX `idx_malware_name` ON `malware` (`name`);--> statement-breakpoint
CREATE INDEX `idx_parent_types` ON `relationship` ((CAST(`parent_types` AS CHAR(32) ARRAY)));--> statement-breakpoint
CREATE INDEX `idx_tag_name` ON `stub` (`name`);