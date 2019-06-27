import { addSettings } from '../src/domain/settings';
import { addMarkingDefinition } from '../src/domain/markingDefinition';

module.exports.up = async next => {
  await addSettings(
    {},
    {
      platform_title: 'Cyber threat intelligence platform',
      platform_email: '',
      platform_url: '',
      platform_language: 'auto',
      platform_external_auth: true,
      platform_registration: false,
      platform_demo: false
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:WHITE',
      color: '',
      level: 1
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:GREEN',
      color: '',
      level: 2
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:AMBER',
      color: '',
      level: 3
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:RED',
      color: '',
      level: 4
    }
  );
  next();
};

module.exports.down = async next => {
  next();
};
