import 'source-map-support/register';
import { boot } from './boot';

// register modules
import './modules/channel/channel';

// noinspection JSIgnoredPromiseFromCall
boot();
