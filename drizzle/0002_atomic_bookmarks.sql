CREATE TABLE `investigation_bookmarks` (
	`owner` text NOT NULL,
	`alert_id` text NOT NULL,
	`attempt` integer NOT NULL,
	`event_id` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`owner`, `alert_id`, `attempt`, `event_id`)
);
--> statement-breakpoint
CREATE INDEX `idx_investigation_bookmarks_owner_alert` ON `investigation_bookmarks` (`owner`,`alert_id`,`attempt`);
