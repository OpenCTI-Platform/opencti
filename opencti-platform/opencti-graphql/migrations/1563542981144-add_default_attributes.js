import { addAttribute } from '../src/domain/attribute';

module.exports.up = async next => {
  await addAttribute({
    type: 'report_class',
    value: 'external'
  });
  await addAttribute({
    type: 'report_class',
    value: 'internal'
  });
  await addAttribute({
    type: 'role_played',
    value: 'C2 server'
  });
  await addAttribute({
    type: 'role_played',
    value: 'Relay node'
  });
  next();
};

module.exports.down = async next => {
  next();
};
