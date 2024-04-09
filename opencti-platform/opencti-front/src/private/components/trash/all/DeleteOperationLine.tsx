import React from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ItemMarkings from '../../../../components/ItemMarkings';
import Box from '@mui/material/Box';
import { DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { DeleteOperationLine_node$key } from './__generated__/DeleteOperationLine_node.graphql';
import DeleteOperationPopover from './DeleteOperationPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import ItemEntityType from '../../../../components/ItemEntityType';

const DeleteOperationFragment = graphql`
  fragment DeleteOperationLine_node on DeleteOperation {
    id
    main_entity_name
    main_entity_type
    deletedBy {
      id
      name
    }
    timestamp
    deleted_elements {
      id
    }
  }
`;

interface DeleteOperationLineComponentProps {
  dataColumns: DataColumns;
  node: DeleteOperationLine_node$key;
  paginationOptions: DeleteOperationsLinesPaginationQuery$variables;
}

const cellSx = {
  height: 20,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: '10px',
};

const listItemSx = {
  paddingLeft: '10px',
  height: 50,
};

export const DeleteOperationLine: React.FC<DeleteOperationLineComponentProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { fldt } = useFormatter();
  const data = useFragment(DeleteOperationFragment, node);
  return (
    <ListItem
      // classes={{ root: classes.item }}
      sx={listItemSx}
      divider={true}
    >
      <ListItemIcon>
        <ItemIcon type={data.main_entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <Box sx={{ ...cellSx, width: dataColumns.main_entity_type.width ?? 'inherit' }}>
              <ItemEntityType entityType={data.main_entity_type} />
            </Box>
            <Box sx={{ ...cellSx, width: dataColumns.main_entity_name.width ?? 'inherit' }}>
              {data.main_entity_name}
            </Box>
            <Box sx={{ ...cellSx, width: dataColumns.deletedBy.width ?? 'inherit' }}>
              {data.deletedBy?.name}
            </Box>
            <Box sx={{ ...cellSx, width: dataColumns.timestamp.width ?? 'inherit' }}>
              {fldt(data.timestamp)}
            </Box>
            <Box sx={{ ...cellSx, width: dataColumns.objectMarking.width ?? 'inherit' }}>
                <ItemMarkings variant="inList" markingDefinitions={data.objectMarking ?? []} limit={1}/>
            </Box>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <DeleteOperationPopover
          mainEntityId={data.id}
          deletedCount={data.deleted_elements.length}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

interface DeleteOperationLineDummyProps {
  dataColumns: DataColumns;
}

export const DeleteOperationLineDummy: React.FC<DeleteOperationLineDummyProps> = ({ dataColumns }) => {
  return (
    <ListItem
      sx={listItemSx}
      divider={true}
    >
      <ListItemIcon>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <Box
                key={value.label}
                sx={{ ...cellSx, width: value.width ?? 'inherit' }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </Box>
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
