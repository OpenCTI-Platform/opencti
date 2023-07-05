import type { BasicStoreEntity } from './store';

export interface BasicStoreSettingsMessage {
  id: string
  message: string
  activated: boolean
  updated_at: Date
  dismissible: boolean
  color: string
}

export interface BasicStoreSettings extends BasicStoreEntity {
  platform_email: string
  platform_organization: string
  platform_theme_dark_background: string
  enterprise_edition?: Date
  activity_listeners_ids?: string[]
  activity_listeners_users?: string[]
  messages?: BasicStoreSettingsMessage[]
}
