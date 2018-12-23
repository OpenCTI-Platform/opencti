import { head } from 'ramda';
import {
  deleteByID,
  loadByID,
  loadFirst,
  notify,
  now,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const getSettings = () => loadFirst('Settings').then(result => result);

export const updateSettings = async (user, id, settings) =>
  loadByID(id).then(currentSettings => {
    console.log(id);
    console.log(currentSettings);
    const createSettings = qk(`insert $settings isa Settings 
    has platform_title "${settings.platform_title}";
    $settings has platform_email "${settings.platform_email}";
    $settings has platform_url "${settings.platform_url}";
    $settings has platform_language "${settings.platform_language}";
    $settings has platform_external_auth ${settings.platform_external_auth};
    $settings has platform_registration ${settings.platform_registration};
    $settings has created_at ${now()};
    $settings has updated_at ${now()};
  `);
    if (currentSettings !== undefined) {
      return deleteByID(id).then(() => {
        createSettings.then(result => {
          const { data } = result;
          return loadByID(head(data).settings.id).then(created =>
            notify(BUS_TOPICS.Settings.UPDATE_TOPIC, created)
          );
        });
      });
    }
    return createSettings.then(result => {
      const { data } = result;
      return loadByID(head(data).settings.id).then(created =>
        notify(BUS_TOPICS.Settings.UPDATE_TOPIC, created)
      );
    });
  });
