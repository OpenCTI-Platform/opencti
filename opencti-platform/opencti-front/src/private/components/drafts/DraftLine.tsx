import React from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Skeleton from '@mui/material/Skeleton';
import IconButton from '@mui/material/IconButton';
import { MoreVert } from '@mui/icons-material';
import DraftPopover from '@components/drafts/DraftPopover';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { DraftLine_node$key } from '@components/drafts/__generated__/DraftLine_node.graphql';
import ItemIcon from '../../../components/ItemIcon';
import { DataColumns } from '../../../components/list_lines';

const DraftLineFragment = graphql`
  fragment DraftLine_node on DraftWorkspace {
    id
    entity_type
    name
  }
`;

interface DraftLineProps {
  dataColumns: DataColumns;
  node: DraftLine_node$key;
  paginationOptions: DraftsLinesPaginationQuery$variables;
}

export const DraftLine: React.FC<DraftLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const data = useFragment(DraftLineFragment, node);
  return (
    <ListItem
      divider={true}
      style={{ paddingLeft: 10 }}
    >
      <ListItemIcon>
        <ItemIcon type={data.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div style={{ width: dataColumns.name.width }}>
            {data.name}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <DraftPopover
          draftId={data.id}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

interface DraftLineDummyProps {
  dataColumns: DataColumns;
}

export const DraftLineDummy: React.FC<DraftLineDummyProps> = ({
  dataColumns,
}) => {
  return (
    <ListItem
      divider={true}
    >
      <ListItemIcon>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value, idx) => (
              <div
                key={idx}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <IconButton disabled={true} aria-haspopup="true" size="large">
          <MoreVert />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
