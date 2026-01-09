import React from 'react';
import { useNavigate } from 'react-router-dom';
import Security from '../utils/Security';
import { SETTINGS_SETACCESSES } from '../utils/hooks/useGranted';
import { Stack } from '@mui/material';
import Tag from '@common/tag/Tag';

const systemUsers = [
  '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505', // SYSTEM
  '82ed2c6c-eb27-498e-b904-4f2abc04e05f', // RETENTION MANAGER
  'c49fe040-2dad-412d-af07-ce639204ad55', // AUTOMATION MANAGER
  'f9d7b43f-b208-4c56-8637-375a1ce84943', // RULE MANAGER
  '31afac4e-6b99-44a0-b91b-e04738d31461', // REDACTED USER
];

interface ItemCreatorsProps {
  creators: readonly {
    readonly id: string;
    readonly name: string;
  }[];
}

const ItemCreators = ({ creators }: ItemCreatorsProps) => {
  const navigate = useNavigate();

  return (
    <Stack direction="row" gap={1} flexWrap="wrap">
      {creators.map((creator) => {
        return (
          <Security
            key={creator.id}
            needs={[SETTINGS_SETACCESSES]}
            placeholder={(
              <Tag label={creator.name} />
            )}
          >
            {systemUsers.includes(creator.id) ? (
              <Tag label={creator.name} />
            ) : (
              <Tag
                key={creator.id}
                label={creator.name}
                onClick={() => navigate(`/dashboard/settings/accesses/users/${creator.id}`)}
              />
            )}
          </Security>
        );
      })}
    </Stack>
  );
};

export default ItemCreators;
