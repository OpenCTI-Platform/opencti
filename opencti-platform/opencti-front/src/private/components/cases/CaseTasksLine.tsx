import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import ItemStatus from '../../../components/ItemStatus';
import { DataColumns } from '../../../components/list_lines';
import { Theme } from '../../../components/Theme';
import StixCoreObjectLabels from '../common/stix_core_objects/StixCoreObjectLabels';
import {
  CaseTasksLine_data$data,
  CaseTasksLine_data$key,
} from './__generated__/CaseTasksLine_data.graphql';
import CaseTasksPopover from './case_task/CaseTasksPopover';
import { CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

const dataColumns: DataColumns = {
  name: {
    label: 'Title',
    width: '25%',
    isSortable: true,
    render: (task: CaseTasksLine_data$data) => task.name,
  },
  dueDate: {
    label: 'Due Date',
    width: '15%',
    isSortable: true,
    render: (task: CaseTasksLine_data$data, { fldt }) => fldt(task.dueDate),
  },
  objectAssignee: {
    label: 'Assignees',
    width: '25%',
    isSortable: true,
    render: (task: CaseTasksLine_data$data) => task.objectAssignee?.edges?.map(({ node }) => node.name).join(', '),
  },
  objectLabel: {
    label: 'Labels',
    width: '20%',
    isSortable: true,
    render: (task: CaseTasksLine_data$data) => (
      <StixCoreObjectLabels variant="inList" labels={task.objectLabel} />
    ),
  },
  x_opencti_workflow_id: {
    label: 'Status',
    width: '15%',
    isSortable: true,
    render: (task) => (
      <ItemStatus
        status={task.status}
        variant="inList"
        disabled={!task.workflowEnabled}
      />
    ),
  },
};

const CaseTaskFragment = graphql`
  fragment CaseTasksLine_data on CaseTask {
    id
    name
    dueDate
    description
    workflowEnabled
    objectMarking {
      edges {
        node {
          definition
          definition_type
          id
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectAssignee {
      edges {
        node {
          entity_type
          id
          name
        }
      }
    }
    status {
      template {
        name
        color
      }
    }
  }
`;

interface CaseTasksLineProps {
  data: CaseTasksLine_data$key;
  paginationOptions: CaseTasksLinesQuery$variables;
  caseId: string;
}

const CaseTasksLine: FunctionComponent<CaseTasksLineProps> = ({
  data,
  paginationOptions,
  caseId,
}) => {
  const classes = useStyles();
  const { fldt } = useFormatter();
  const task = useFragment(CaseTaskFragment, data);
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Case-Task"></ItemIcon>
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(task, { fldt })}
              </div>
            ))}
          </>
        }
      />
      <ListItemSecondaryAction>
        <CaseTasksPopover
          caseId={caseId}
          task={task}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export default CaseTasksLine;
