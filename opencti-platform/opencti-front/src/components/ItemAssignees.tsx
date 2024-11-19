import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import { CancelOutlined, PersonOutline } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { stixDomainObjectMutation } from '@components/common/stix_domain_objects/StixDomainObjectHeader';
import Tooltip from '@mui/material/Tooltip';
import { truncate } from '../utils/String';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import type { Theme } from './Theme';
import FieldOrEmpty from './FieldOrEmpty';
import { commitMutation, defaultCommitMutation } from '../relay/environment';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assignees: ReadonlyArray<Node>;
  stixDomainObjectId: string;
};

const ItemAssignees: FunctionComponent<Props> = ({ assignees, stixDomainObjectId }) => {
  const theme = useTheme<Theme>();
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);
  const handleRemoveAssignee = (removedId: string) => {
    const values = assignees.filter((assignee) => assignee.id !== removedId);
    const valuesIds = values.map((value) => value.id);
    commitMutation({
      mutation: stixDomainObjectMutation,
      variables: {
        id: stixDomainObjectId,
        input: {
          key: 'objectAssignee',
          value: valuesIds,
        },
      },
      ...defaultCommitMutation,
    });
  };
  return (
    <FieldOrEmpty source={assignees}>
      {assignees.map((assignee) => (
        <Tooltip key={assignee.id} title={assignee.name}>
          <Chip
            key={assignee.id}
            variant="outlined"
            icon={<PersonOutline color={'primary'} />}
            label={truncate(assignee.name, 25).toUpperCase()}
            style={{
              color: theme.palette.primary.main,
              borderColor: theme.palette.primary.main,
              margin: '0 7px 7px 0',
              borderRadius: theme.borderRadius,
            }}
            onDelete={canUpdateKnowledge ? () => (handleRemoveAssignee(assignee.id)) : undefined}
            deleteIcon={
              <CancelOutlined
                style={{ color: theme.palette.primary.main }}
              />
            }
          />
        </Tooltip>
      ))}
    </FieldOrEmpty>
  );
};

export default ItemAssignees;
