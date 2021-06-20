import 'source-map-support/register';
import { boot } from './boot';

// Add hot module
if (module.hot) {
  module.hot.accept(['./modules', './boot'], boot);
}

// noinspection JSIgnoredPromiseFromCall
boot();
