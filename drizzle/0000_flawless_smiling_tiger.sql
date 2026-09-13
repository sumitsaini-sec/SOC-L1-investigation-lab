CREATE TABLE `actions` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`alert_id` text NOT NULL,
	`target` text NOT NULL,
	`action` text NOT NULL,
	`time` text NOT NULL,
	`reason` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_actions_owner_alert` ON `actions` (`owner`,`alert_id`);--> statement-breakpoint
CREATE INDEX `idx_actions_target` ON `actions` (`owner`,`target`);--> statement-breakpoint
CREATE TABLE `alerts` (
	`id` text PRIMARY KEY NOT NULL,
	`incident_id` text,
	`time` text NOT NULL,
	`severity` text NOT NULL,
	`family` text NOT NULL,
	`user` text NOT NULL,
	`host` text NOT NULL,
	`source_ip` text NOT NULL,
	`domain` text NOT NULL,
	`rule_id` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_alerts_time` ON `alerts` (`time`);--> statement-breakpoint
CREATE INDEX `idx_alerts_incident` ON `alerts` (`incident_id`);--> statement-breakpoint
CREATE INDEX `idx_alerts_host` ON `alerts` (`host`);--> statement-breakpoint
CREATE INDEX `idx_alerts_user` ON `alerts` (`user`);--> statement-breakpoint
CREATE INDEX `idx_alerts_ip` ON `alerts` (`source_ip`);--> statement-breakpoint
CREATE INDEX `idx_alerts_domain` ON `alerts` (`domain`);--> statement-breakpoint
CREATE INDEX `idx_alerts_filter` ON `alerts` (`family`,`severity`);--> statement-breakpoint
CREATE TABLE `cases` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`alert_id` text NOT NULL,
	`status` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_cases_owner` ON `cases` (`owner`);--> statement-breakpoint
CREATE INDEX `idx_cases_alert` ON `cases` (`owner`,`alert_id`);--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`alert_id` text NOT NULL,
	`incident_id` text,
	`timestamp` text NOT NULL,
	`kind` text NOT NULL,
	`event_id` integer NOT NULL,
	`user` text NOT NULL,
	`host` text NOT NULL,
	`source_ip` text NOT NULL,
	`domain` text NOT NULL,
	`hash` text NOT NULL,
	`process_name` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_events_alert_time` ON `events` (`alert_id`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_events_host_time` ON `events` (`host`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_events_user_time` ON `events` (`user`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_events_ip_time` ON `events` (`source_ip`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_events_kind_time` ON `events` (`kind`,`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_events_domain` ON `events` (`domain`);--> statement-breakpoint
CREATE INDEX `idx_events_hash` ON `events` (`hash`);--> statement-breakpoint
CREATE INDEX `idx_events_event_id` ON `events` (`event_id`);--> statement-breakpoint
CREATE INDEX `idx_events_time` ON `events` (`timestamp`);--> statement-breakpoint
CREATE TABLE `scenario_truth` (
	`alert_id` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `hosts` (
	`id` text PRIMARY KEY NOT NULL,
	`user` text NOT NULL,
	`ip` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_hosts_user` ON `hosts` (`user`);--> statement-breakpoint
CREATE INDEX `idx_hosts_ip` ON `hosts` (`ip`);--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `investigations` (
	`owner` text NOT NULL,
	`alert_id` text NOT NULL,
	`status` text NOT NULL,
	`started_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`submitted_at` text,
	`data` text NOT NULL,
	PRIMARY KEY(`owner`, `alert_id`)
);
--> statement-breakpoint
CREATE INDEX `idx_investigations_owner_status` ON `investigations` (`owner`,`status`);--> statement-breakpoint
CREATE TABLE `iocs` (
	`value` text PRIMARY KEY NOT NULL,
	`type` text NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `detection_rules` (
	`id` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `seed_batches` (
	`id` text PRIMARY KEY NOT NULL,
	`time` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `settings` (
	`owner` text PRIMARY KEY NOT NULL,
	`data` text NOT NULL
);
