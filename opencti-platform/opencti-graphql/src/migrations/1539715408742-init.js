import { addMarkingDefinition } from '../domain/markingDefinition';

module.exports.up = async next => {
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:WHITE',
      color: '#ffffff',
      level: 1,
      stix_id_key: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:GREEN',
      color: '#2e7d32',
      level: 2,
      stix_id_key: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:AMBER',
      color: '#d84315',
      level: 3,
      stix_id_key: '"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
    }
  );
  await addMarkingDefinition(
    {},
    {
      definition_type: 'TLP',
      definition: 'TLP:RED',
      color: '#c62828',
      level: 4,
      stix_id_key: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed'
    }
  );
  next();
};

module.exports.down = async next => {
  next();
};
