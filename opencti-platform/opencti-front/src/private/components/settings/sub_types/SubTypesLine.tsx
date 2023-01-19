import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import {
  KeyboardArrowRightOutlined,
  CheckCircleOutlined,
  DoNotDisturbOnOutlined,
} from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import Checkbox from '@mui/material/Checkbox';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { SubType_subType$data } from './__generated__/SubType_subType.graphql';
import { Theme } from '../../../../components/Theme';

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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

interface SubTypeLineProps {
  node: SubType_subType$data;
  dataColumns: DataColumns;
  selectedElements: Record<string, { id: string }>;
  deSelectedElements: Record<string, { id: string }>;
  selectAll: boolean;
  onToggleEntity: (entity: { id: string }, event: React.SyntheticEvent) => void;
  onToggleShiftEntity: (
    index: number,
    entity: { id: string },
    event: React.SyntheticEvent
  ) => void;
  index: number;
}

const SubTypeLine: FunctionComponent<SubTypeLineProps> = ({
  node,
  dataColumns,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <ListItemButton
      key={node.id}
      divider={true}
      classes={{ root: classes.item }}
      component={Link}
      to={`/dashboard/settings/entity_types/${node.id}`}
    >
      <ListItemIcon
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, { id: node.id }, event)
          : onToggleEntity({ id: node.id }, event))
        }
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(node.id in (deSelectedElements || {})))
            || node.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={node.id} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              {t(`entity_${node.label}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.workflow_status.width }}
            >
              {node.workflowEnabled ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary" />
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.enforce_reference.width }}
            >
              {node?.settings?.enforce_reference ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined
                  fontSize="small"
                  color={
                    node?.settings?.enforce_reference === null
                      ? 'disabled'
                      : 'primary'
                  }
                />
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.automatic_references.width }}
            >
              {node?.settings?.platform_entity_files_ref ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined
                  fontSize="small"
                  color={
                    node?.settings?.platform_entity_files_ref === null
                      ? 'disabled'
                      : 'primary'
                  }
                />
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.hidden.width }}
            >
              {node?.settings?.platform_hidden_type ? (
                <CheckCircleOutlined fontSize="small" color="success" />
              ) : (
                <DoNotDisturbOnOutlined
                  fontSize="small"
                  color={
                    node?.settings?.platform_hidden_type === null
                      ? 'disabled'
                      : 'primary'
                  }
                />
              )}
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default SubTypeLine;

export const SubTypeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem divider={true} classes={{ root: classes.item }}>
      <ListItemIcon style={{ minWidth: 40 }}>
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItem style={{ paddingLeft: 0 }}>
        <ListItemIcon>
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
              {Object.values(dataColumns).map((value) => (
                <div
                  key={value.label}
                  className={classes.bodyItem}
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
        <ListItemIcon>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    </ListItem>
  );
};
