CREATE TABLE `account_research` (
	`account_id` integer PRIMARY KEY NOT NULL,
	`company_snapshot` text DEFAULT '' NOT NULL,
	`recent_news` text DEFAULT '' NOT NULL,
	`funding` text DEFAULT '' NOT NULL,
	`stack` text DEFAULT '' NOT NULL,
	`hiring` text DEFAULT '' NOT NULL,
	`vendors` text DEFAULT '' NOT NULL,
	`triggers` text DEFAULT '' NOT NULL,
	`pains` text DEFAULT '' NOT NULL,
	`gaps` text DEFAULT '' NOT NULL,
	`why_account` text DEFAULT '' NOT NULL,
	`why_now` text DEFAULT '' NOT NULL,
	`primary_pain` text DEFAULT '' NOT NULL,
	`wedge` text DEFAULT '' NOT NULL,
	`buyer` text DEFAULT '' NOT NULL,
	`proof` text DEFAULT '' NOT NULL,
	`expansion` text DEFAULT '' NOT NULL,
	`validation_step` text DEFAULT '' NOT NULL,
	`final_thesis` text DEFAULT '' NOT NULL,
	`economic_buyer` text DEFAULT '' NOT NULL,
	`technical_buyer` text DEFAULT '' NOT NULL,
	`champion` text DEFAULT '' NOT NULL,
	`users_influence` text DEFAULT '' NOT NULL,
	`blockers` text DEFAULT '' NOT NULL,
	`procurement` text DEFAULT '' NOT NULL,
	`warm_path` text DEFAULT '' NOT NULL,
	`sources` text DEFAULT '' NOT NULL,
	`confidence` text DEFAULT '' NOT NULL,
	`last_verified` text DEFAULT '' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `accounts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`company` text NOT NULL,
	`region` text DEFAULT '' NOT NULL,
	`industry` text DEFAULT '' NOT NULL,
	`size` text DEFAULT 'Scale-up' NOT NULL,
	`incumbent` text DEFAULT '' NOT NULL,
	`products` text DEFAULT '' NOT NULL,
	`pain` text DEFAULT '' NOT NULL,
	`trigger` text DEFAULT '' NOT NULL,
	`contact` text DEFAULT '' NOT NULL,
	`path` text DEFAULT '' NOT NULL,
	`stage` text DEFAULT 'Target' NOT NULL,
	`fit` text DEFAULT 'Medium' NOT NULL,
	`next_action` text DEFAULT '' NOT NULL,
	`due_on` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `accounts_stage_idx` ON `accounts` (`stage`);--> statement-breakpoint
CREATE INDEX `accounts_company_idx` ON `accounts` (`company`);--> statement-breakpoint
CREATE TABLE `audit_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`actor_user_id` integer,
	`actor_email` text DEFAULT '' NOT NULL,
	`action` text NOT NULL,
	`entity_type` text DEFAULT '' NOT NULL,
	`entity_id` text DEFAULT '' NOT NULL,
	`metadata` text DEFAULT '{}' NOT NULL,
	`ip_hash` text DEFAULT '' NOT NULL,
	`outcome` text DEFAULT 'success' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`actor_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `audit_actor_idx` ON `audit_log` (`actor_user_id`);--> statement-breakpoint
CREATE INDEX `audit_created_idx` ON `audit_log` (`created_at`);--> statement-breakpoint
CREATE INDEX `audit_entity_idx` ON `audit_log` (`entity_type`,`entity_id`);--> statement-breakpoint
CREATE TABLE `catalog_sync_runs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`started_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`finished_at` integer,
	`status` text DEFAULT 'running' NOT NULL,
	`source_kind` text DEFAULT 'local-corpus' NOT NULL,
	`products_seen` integer DEFAULT 0 NOT NULL,
	`products_created` integer DEFAULT 0 NOT NULL,
	`products_updated` integer DEFAULT 0 NOT NULL,
	`error` text DEFAULT '' NOT NULL,
	`triggered_by` integer,
	FOREIGN KEY (`triggered_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `sync_started_idx` ON `catalog_sync_runs` (`started_at`);--> statement-breakpoint
CREATE TABLE `motions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`opportunity` text NOT NULL,
	`trigger_signals` text DEFAULT '' NOT NULL,
	`icp` text DEFAULT '' NOT NULL,
	`discovery_questions` text DEFAULT '' NOT NULL,
	`wedge_product` text DEFAULT '' NOT NULL,
	`poc_strategy` text DEFAULT '' NOT NULL,
	`success_metrics` text DEFAULT '' NOT NULL,
	`expansion_path` text DEFAULT '' NOT NULL,
	`risks` text DEFAULT '' NOT NULL,
	`evidence_required` text DEFAULT '' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `product_evidence` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`product_id` integer NOT NULL,
	`level` text DEFAULT 'Assumption' NOT NULL,
	`statement` text DEFAULT '' NOT NULL,
	`can_say` text DEFAULT 'No' NOT NULL,
	`source` text DEFAULT '' NOT NULL,
	`confidence` text DEFAULT 'Low' NOT NULL,
	`verified_on` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '' NOT NULL,
	`position` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `evidence_product_idx` ON `product_evidence` (`product_id`,`position`);--> statement-breakpoint
CREATE INDEX `evidence_can_say_idx` ON `product_evidence` (`can_say`);--> statement-breakpoint
CREATE TABLE `products` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`category` text DEFAULT '' NOT NULL,
	`product` text NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`competitors` text DEFAULT '' NOT NULL,
	`use_cases` text DEFAULT '' NOT NULL,
	`industries` text DEFAULT '' NOT NULL,
	`company_size` text DEFAULT '' NOT NULL,
	`customer_gate` text DEFAULT '' NOT NULL,
	`pain_points` text DEFAULT '' NOT NULL,
	`strengths` text DEFAULT '' NOT NULL,
	`weaknesses` text DEFAULT '' NOT NULL,
	`product_entry` text DEFAULT '' NOT NULL,
	`bd_motion` text DEFAULT '' NOT NULL,
	`notes` text DEFAULT '' NOT NULL,
	`source` text DEFAULT '' NOT NULL,
	`priority` text DEFAULT 'P3' NOT NULL,
	`knowledge` text DEFAULT 'To Learn' NOT NULL,
	`confidence` text DEFAULT 'Hypothesis' NOT NULL,
	`status` text DEFAULT 'Not Reviewed' NOT NULL,
	`owner` text DEFAULT '' NOT NULL,
	`commercial_category` text DEFAULT 'Standalone / Other' NOT NULL,
	`sell_mode` text DEFAULT 'Standalone' NOT NULL,
	`solution_story` text DEFAULT '' NOT NULL,
	`primary_competitor` text DEFAULT '' NOT NULL,
	`reference_customers` text DEFAULT '' NOT NULL,
	`tencent_edge` text DEFAULT '' NOT NULL,
	`messaging_technical` text DEFAULT '' NOT NULL,
	`messaging_business` text DEFAULT '' NOT NULL,
	`messaging_executive` text DEFAULT '' NOT NULL,
	`messaging_safe_claim` text DEFAULT '' NOT NULL,
	`discovery` text DEFAULT '' NOT NULL,
	`buying_signals` text DEFAULT '' NOT NULL,
	`red_flags` text DEFAULT '' NOT NULL,
	`proof_required` text DEFAULT '' NOT NULL,
	`objections` text DEFAULT '' NOT NULL,
	`replacements` text DEFAULT '' NOT NULL,
	`learning_checklist` text DEFAULT '' NOT NULL,
	`score_demand` integer DEFAULT 3 NOT NULL,
	`score_right_to_win` integer DEFAULT 3 NOT NULL,
	`score_entry` integer DEFAULT 3 NOT NULL,
	`score_poc` integer DEFAULT 3 NOT NULL,
	`score_expansion` integer DEFAULT 3 NOT NULL,
	`score_revenue` integer DEFAULT 3 NOT NULL,
	`score_rationale` text DEFAULT '' NOT NULL,
	`score_validation` text DEFAULT '' NOT NULL,
	`upstream_code` text,
	`upstream_synced_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `products_upstream_code_unique` ON `products` (`upstream_code`);--> statement-breakpoint
CREATE INDEX `products_priority_idx` ON `products` (`priority`);--> statement-breakpoint
CREATE INDEX `products_category_idx` ON `products` (`category`);--> statement-breakpoint
CREATE INDEX `products_commercial_idx` ON `products` (`commercial_category`);--> statement-breakpoint
CREATE INDEX `products_status_idx` ON `products` (`status`);--> statement-breakpoint
CREATE TABLE `rate_limits` (
	`key` text PRIMARY KEY NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`window_started_at` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `rate_limits_expiry_idx` ON `rate_limits` (`expires_at`);--> statement-breakpoint
CREATE TABLE `review_answers` (
	`question_index` integer NOT NULL,
	`user_id` integer NOT NULL,
	`answer` text DEFAULT '' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	PRIMARY KEY(`user_id`, `question_index`),
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `review_user_idx` ON `review_answers` (`user_id`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` integer NOT NULL,
	`token_hash` text NOT NULL,
	`user_agent_hash` text DEFAULT '' NOT NULL,
	`ip_hash` text DEFAULT '' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`last_seen_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`absolute_expires_at` integer NOT NULL,
	`revoked_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sessions_token_hash_unique` ON `sessions` (`token_hash`);--> statement-breakpoint
CREATE INDEX `sessions_user_idx` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sessions_expiry_idx` ON `sessions` (`absolute_expires_at`);--> statement-breakpoint
CREATE TABLE `sop_steps` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`body` text DEFAULT '' NOT NULL,
	`position` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `sop_position_idx` ON `sop_steps` (`position`);--> statement-breakpoint
CREATE TABLE `todos` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`title` text NOT NULL,
	`detail` text DEFAULT '' NOT NULL,
	`owner` text DEFAULT 'Me' NOT NULL,
	`priority` text DEFAULT 'P2' NOT NULL,
	`status` text DEFAULT 'Backlog' NOT NULL,
	`due_on` text DEFAULT '' NOT NULL,
	`link` text DEFAULT '' NOT NULL,
	`position` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `todos_status_idx` ON `todos` (`status`,`position`);--> statement-breakpoint
CREATE TABLE `translations` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`entity_type` text NOT NULL,
	`entity_id` integer NOT NULL,
	`field` text NOT NULL,
	`locale` text NOT NULL,
	`value` text NOT NULL,
	`source_locale` text NOT NULL,
	`source_hash` text NOT NULL,
	`origin` text DEFAULT 'machine' NOT NULL,
	`status` text DEFAULT 'needs-review' NOT NULL,
	`reviewed_by` integer,
	`reviewed_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`reviewed_by`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `translations_target_unique` ON `translations` (`entity_type`,`entity_id`,`field`,`locale`);--> statement-breakpoint
CREATE INDEX `translations_status_idx` ON `translations` (`status`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`email` text NOT NULL,
	`display_name` text DEFAULT '' NOT NULL,
	`password_hash` text NOT NULL,
	`role` text DEFAULT 'viewer' NOT NULL,
	`locale` text DEFAULT 'en' NOT NULL,
	`failed_login_count` integer DEFAULT 0 NOT NULL,
	`locked_until` integer,
	`last_login_at` integer,
	`is_active` integer DEFAULT true NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);