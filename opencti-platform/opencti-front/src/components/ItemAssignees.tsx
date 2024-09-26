import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import { truncate } from '../utils/String';
import { hexToRGB } from '../utils/Colors';
import { CancelOutlined } from '@mui/icons-material';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../utils/hooks/useGranted';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import FieldOrEmpty from './FieldOrEmpty';

type Node = {
  readonly entity_type: string;
  readonly id: string;
  readonly name: string;
};

type Props = {
  assignees: ReadonlyArray<Node>;
};

const ItemAssignees: FunctionComponent<Props> = ({ assignees }) => {
  const theme = useTheme<Theme>();
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);
  const handleRemoveAssignee = (assigneeId: string) => {
    console.log(assigneeId);
    // TODO : Mutation
  };
  return (
    <FieldOrEmpty source={assignees}>
      {assignees.map((assignee) => (
        <Chip
          key={assignee.id}
          variant="outlined"
          label={truncate(assignee.name, 25)}
          style={{
            color: theme.palette.primary.main,
            borderColor: theme.palette.primary.main,
            backgroundColor: hexToRGB(theme.palette.primary.main),
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
      ))}
    </FieldOrEmpty>
  );
};

export default ItemAssignees;
