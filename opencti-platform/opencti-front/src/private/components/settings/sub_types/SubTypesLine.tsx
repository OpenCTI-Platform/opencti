import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
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
import { Theme } from '../../../../components/Theme';
import { SubTypesLine_node$key } from './__generated__/SubTypesLine_node.graphql';

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
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

const subTypesLinesFragment = graphql`
  fragment SubTypesLine_node on SubType {
    id
    label
    workflowEnabled
    settings {
      id
      enforce_reference
      platform_entity_files_ref
      platform_hidden_type
      target_type
      availableSettings
    }
    statuses {
      id
      order
      template {
        name
        color
      }
    }
  }
`;

interface SubTypeLineProps {
  node: SubTypesLine_node$key;
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
  const nodeSubType = useFragment(subTypesLinesFragment, node);

  const renderOptionIcon = (option: string) => {
    if (!nodeSubType.settings?.availableSettings?.includes(option)) {
      return <DoNotDisturbOnOutlined fontSize="small" color={'disabled'} />;
    }
    if ((nodeSubType.settings as never)?.[option] === true) {
      return <CheckCircleOutlined fontSize="small" color="success" />;
    }
    return <DoNotDisturbOnOutlined fontSize="small" color="primary" />;
  };
  const renderWorkflowStatus = () => {
    if (!nodeSubType.settings?.availableSettings?.includes('workflow_configuration')) {
      return <DoNotDisturbOnOutlined fontSize="small" color={'disabled'} />;
    }
    if (nodeSubType.workflowEnabled) {
      return <CheckCircleOutlined fontSize="small" color="success" />;
    }
    return <DoNotDisturbOnOutlined fontSize="small" color="primary" />;
  };
  return (
    <ListItemButton
      key={nodeSubType.id}
      divider={true}
      classes={{ root: classes.item }}
      component={Link}
      to={`/dashboard/settings/customization/entity_types/${nodeSubType.id}`}
    >
      <ListItemIcon
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, { id: nodeSubType.id }, event)
          : onToggleEntity({ id: nodeSubType.id }, event))
        }
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(nodeSubType.id in (deSelectedElements || {})))
            || nodeSubType.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={nodeSubType.id} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              {t(`entity_${nodeSubType.label}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.workflow_status.width }}
            >
              {renderWorkflowStatus()}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.enforce_reference.width }}
            >
              {renderOptionIcon('enforce_reference')}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.automatic_references.width }}
            >
              {renderOptionIcon('platform_entity_files_ref')}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.hidden.width }}
            >
              {renderOptionIcon('platform_hidden_type')}
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
