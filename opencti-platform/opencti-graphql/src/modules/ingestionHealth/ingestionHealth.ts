import { registerSettingsAttribute } from '../settings/settings-attributes';
import { ingestionHealthSettingsAttribute } from './ingestionHealth-attributes';

// The ingestion health settings are stored in the platform settings, read and edited through ingestionHealth-domain
registerSettingsAttribute(ingestionHealthSettingsAttribute);
