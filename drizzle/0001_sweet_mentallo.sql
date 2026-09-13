CREATE TABLE `attempts` (
	`owner` text NOT NULL,
	`alert_id` text NOT NULL,
	`attempt` integer NOT NULL,
	`data` text NOT NULL,
	PRIMARY KEY(`owner`, `alert_id`, `attempt`)
);
