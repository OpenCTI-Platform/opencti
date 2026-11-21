import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { graphql, useFragment } from 'react-relay';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../components/list_lines';
import { CaseTemplateTasksLine_node$key } from './__generated__/CaseTemplateTasksLine_node.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { CaseTemplateTasksLinesPaginationQuery$data } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksPopover from './CaseTemplateTasksPopover';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

export const CaseTemplateTasksLineFragment = graphql`
  fragment CaseTemplateTasksLine_node on TaskTemplate {
    id
    name
    description
  }
`;

interface CaseTemplateTasksLineProps {
  node: CaseTemplateTasksLine_node$key;
  dataColumns: DataColumns;
  paginationOptions: CaseTemplateTasksLinesPaginationQuery$data;
}

export const CaseTemplateTasksLine: FunctionComponent<
  CaseTemplateTasksLineProps
> = ({ node, dataColumns, paginationOptions }) => {
  const task = useFragment(CaseTemplateTasksLineFragment, node);

  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <CaseTemplateTasksPopover
          paginationOptions={paginationOptions}
          task={task}
        />
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type="Task" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(task)}
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

interface CaseTemplateLineDummyProps {
  dataColumns: DataColumns;
}

export const CaseTemplateTasksLineDummy: FunctionComponent<
  CaseTemplateLineDummyProps
> = ({ dataColumns }) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon
        sx={{ color: 'grey.700' }}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          disabled={true}
        />
      </ListItemIcon>
      <ListItemIcon sx={{ color: 'grey.700' }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map(({ label, width }) => (
              <BodyItem key={label} style={{ width }}>
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={width}
                  height="100%"
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
