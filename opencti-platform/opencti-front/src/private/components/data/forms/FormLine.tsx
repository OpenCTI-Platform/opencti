import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { KeyboardArrowRightOutlined, AssignmentOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import Chip from '@mui/material/Chip';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { FormLine_node$key } from './__generated__/FormLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import FormPopover from './FormPopover';

// Styles
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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700] ?? '',
  },
}));

const formLineFragment = graphql`
  fragment FormLine_node on Form {
    id
    name
    description
    active
    created_at
    updated_at
    form_schema
  }
`;

interface FormLineComponentProps {
  dataColumns: DataColumns;
  node: FormLine_node$key;
  paginationOptions: any;
}

export const FormLineComponent: FunctionComponent<FormLineComponentProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(formLineFragment, node);

  let mainEntityType = 'Unknown';
  try {
    const schema = JSON.parse(data.form_schema);
    mainEntityType = schema.mainEntityType || 'Unknown';
  } catch {
    // Invalid JSON, keep default
  }

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/data/forms/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <AssignmentOutlined />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.description.width }}
            >
              {data.description || '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.mainEntityType.width }}
            >
              {mainEntityType}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.active.width }}
            >
              <Chip
                label={data.active ? 'Active' : 'Inactive'}
                color={data.active ? 'success' : 'default'}
                size="small"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.updated_at.width }}
            >
              {fd(data.updated_at)}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <FormPopover
          formId={data.id}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export const FormLineDummy: FunctionComponent<{ dataColumns: DataColumns }> = ({
  dataColumns,
}) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.entries(dataColumns).map(([key, column]) => (
              <div
                key={key}
                className={classes.bodyItem}
                style={{ width: column.width }}
              >
                <Skeleton animation="wave" variant="rectangular" width="80%" height={20} />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
