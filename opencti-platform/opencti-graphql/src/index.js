import 'source-map-support/register';
import { boot } from './boot';

// register modules
import './modules/channel/channel';
import './modules/language/language';
import './modules/event/event';
import './modules/narrative/narrative';

// noinspection JSIgnoredPromiseFromCall
boot();
