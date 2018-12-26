import { addSettings, settingsDelete } from '../src/domain/settings';

module.exports.up = async next => {
  await addSettings({
    platform_title: 'Cyber threat intelligence platform',
    platform_email: '',
    platform_url: '',
    platform_language: 'auto',
    platform_external_auth: true,
    platform_registration: false
  });
  next();
};

module.exports.down = async next => {
  next();
};