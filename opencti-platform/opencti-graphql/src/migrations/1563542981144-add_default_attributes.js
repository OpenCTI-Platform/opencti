import { addAttribute } from '../domain/attribute';

export const up = async (next) => {
  await addAttribute({
    type: 'report_class',
    value: 'Threat Report',
  });
  await addAttribute({
    type: 'report_class',
    value: 'Internal Report',
  });
  await addAttribute({
    type: 'role_played',
    value: 'C2 server',
  });
  await addAttribute({
    type: 'role_played',
    value: 'Relay node',
  });
  next();
};

export const down = async (next) => {
  next();
};
