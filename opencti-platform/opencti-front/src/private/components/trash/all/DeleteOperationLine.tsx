import React from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Box from '@mui/material/Box';
import Checkbox from '@mui/material/Checkbox';
import ItemMarkings from '../../../../components/ItemMarkings';
import { DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { DeleteOperationLine_node$data, DeleteOperationLine_node$key } from './__generated__/DeleteOperationLine_node.graphql';
import DeleteOperationPopover from './DeleteOperationPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import ItemEntityType from '../../../../components/ItemEntityType';

const DeleteOperationFragment = graphql`
  fragment DeleteOperationLine_node on DeleteOperation {
    id
    entity_type
    main_entity_name
    main_entity_type
    deletedBy {
      id
      name
    }
    created_at
    deleted_elements {
      id
    }
    objectMarking {
      id
      definition
      definition_type
      x_opencti_color
    }
  }
`;

interface DeleteOperationLineComponentProps {
  dataColumns: DataColumns;
  node: DeleteOperationLine_node$key;
  paginationOptions: DeleteOperationsLinesPaginationQuery$variables;
  selectedElements: Record<string, DeleteOperationLine_node$data>;
  deSelectedElements: Record<string, DeleteOperationLine_node$data>;
  onToggleEntity: (
    entity: DeleteOperationLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: DeleteOperationLine_node$data,
    event?: React.SyntheticEvent,
  ) => void;
  index: number;
}

const cellSx = {
  height: 20,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
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
  selectedElements,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const { fldt } = useFormatter();
  const data = useFragment(DeleteOperationFragment, node);
  return (
    <ListItem
      sx={listItemSx}
      divider={true}
      secondaryAction={(
        <DeleteOperationPopover
          mainEntityId={data.id}
          deletedCount={data.deleted_elements.length}
          paginationOptions={paginationOptions}
        />
      )}
    >
      <ListItemIcon
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon>
        <ItemIcon type={data.main_entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
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
            <Box sx={{ ...cellSx, width: dataColumns.created_at.width ?? 'inherit' }}>
              {fldt(data.created_at)}
            </Box>
            <Box sx={{ ...cellSx, width: dataColumns.objectMarking.width ?? 'inherit' }}>
              <ItemMarkings
                variant="inList"
                markingDefinitions={data.objectMarking ?? []}
                limit={1}
              />
            </Box>
          </div>
        )}
      />
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
      secondaryAction={(
        <IconButton disabled={true} aria-haspopup="true">
          <MoreVert />
        </IconButton>
      )}
    >
      <ListItemIcon>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
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
        )}
      />
    </ListItem>
  );
};
