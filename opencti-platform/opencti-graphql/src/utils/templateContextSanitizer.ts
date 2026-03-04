import { z } from 'zod';

// Strict schemas for sensitive data only

const userSchema = z.object({
  name: z.string().optional().catch(undefined),
  firstname: z.string().optional().catch(undefined),
  lastname: z.string().optional().catch(undefined),
  user_name: z.string().optional().catch(undefined),
  user_email: z.string().optional().catch(undefined),
  api_token: z.string().optional().catch(undefined),
  account_status: z.string().optional().catch(undefined),
}).strip(); // Strip unknown fields instead of rejecting

const settingsSchema = z.object({
  platform_title: z.string().optional().catch(undefined),
  platform_email: z.string().optional().catch(undefined),
  platform_base_url: z.string().optional().catch(undefined),
  platform_theme: z.string().optional().catch(undefined),
}).strip(); // Strip unknown fields instead of rejecting

const notificationSchema = z.object({
  id: z.string().optional().catch(undefined),
  name: z.string().optional().catch(undefined),
  notification_type: z.string().optional().catch(undefined),
  trigger_type: z.string().optional().catch(undefined),
  created: z.string().optional().catch(undefined),
}).strip(); // Strip unknown fields instead of rejecting

// Main SafeTemplateContext schema - single source of truth
const notificationDataSchema = z.object({
  // Strictly controlled fields
  user: userSchema.optional().catch(undefined),
  settings: settingsSchema.optional().catch(undefined),
  notification: notificationSchema.optional().catch(undefined),

  // Arrays - accept any structure (business data)
  content: z.array(z.record(z.unknown())).optional().catch(undefined),
  notification_content: z.array(z.record(z.unknown())).optional().catch(undefined),
  data: z.array(z.record(z.unknown())).optional().catch(undefined),
  users: z.array(z.record(z.unknown())).optional().catch(undefined),

  // Simple string fields
  platform_uri: z.string().optional().catch(undefined),
  doc_uri: z.string().optional().catch(undefined),
  background_color: z.string().optional().catch(undefined),
  url_suffix: z.string().optional().catch(undefined),
  trigger_id: z.string().optional().catch(undefined),
  description: z.string().optional().catch(undefined),

  // Report and other business objects - permissive
  report: z.record(z.unknown()).optional().catch(undefined),

  // Root level fields
  id: z.string().optional().catch(undefined),
  type: z.string().optional().catch(undefined),
  name: z.string().optional().catch(undefined),
  created: z.string().optional().catch(undefined),
  modified: z.string().optional().catch(undefined),
  confidence: z.number().optional().catch(undefined),
  revoked: z.boolean().optional().catch(undefined),
  content_field: z.string().optional().catch(undefined),
  published: z.string().optional().catch(undefined),
  labels: z.union([z.string(), z.array(z.string())]).optional().catch(undefined),
  report_types: z.union([z.string(), z.array(z.string())]).optional().catch(undefined),
}).strip(); // Use strip() instead of strict() to remove unknown fields

// Export inferred types
export type SanitizedUser = z.infer<typeof userSchema>;
export type SanitizedSettings = z.infer<typeof settingsSchema>;
export type SanitizedNotificationData = z.infer<typeof notificationDataSchema>;

export const sanitizeUser = (user: unknown): SanitizedUser => userSchema.parse(user);
export const sanitizeSettings = (settings: unknown): SanitizedSettings => settingsSchema.parse(settings);

/**
 * Sanitizes notification data: remove all data that don't match the expected schema (eg unknown data or data type mismatch)
 * @param data - The template data to sanitize
 */
export const sanitizeNotificationData = (data: unknown): SanitizedNotificationData => notificationDataSchema.parse(data);
