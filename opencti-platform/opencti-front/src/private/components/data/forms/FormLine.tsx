import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { FormLine_node$key } from './__generated__/FormLine_node.graphql';
import { FormLinesPaginationQuery$variables } from './__generated__/FormLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import FormPopover from './FormPopover';
import ItemBoolean from '../../../../components/ItemBoolean';
import ItemIcon from '../../../../components/ItemIcon';

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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
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
  paginationOptions: FormLinesPaginationQuery$variables;
}

export const FormLineComponent: FunctionComponent<FormLineComponentProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n, fd } = useFormatter();
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
      divider={true}
      disablePadding
      secondaryAction={
        <FormPopover
          formId={data.id}
          formName={data.name}
          paginationOptions={paginationOptions}
        />
      }
    >
      <ListItemButton
        classes={{ root: classes.item }}
        component={Link}
        to={`/dashboard/data/ingestion/forms/${data.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={mainEntityType} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
                {data.name}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.description.width }}>
                {data.description || '-'}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.mainEntityType.width }}>
                {mainEntityType}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.active.width }}>
                <ItemBoolean
                  variant="inList"
                  label={data.active ? t_i18n('Active') : t_i18n('Inactive')}
                  status={!!data.active}
                />
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.updated_at.width }}>
                {fd(data.updated_at)}
              </div>
            </div>
          }
        />
      </ListItemButton>
    </ListItem>
  );
};

export const FormLineDummy: FunctionComponent<{ dataColumns: DataColumns }> = ({
  dataColumns,
}) => {
  const classes = useStyles();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={<MoreVert className={classes.itemIconDisabled}/>}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
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
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
            ))}
          </div>
        }
      />
    </ListItem>
  );
};
