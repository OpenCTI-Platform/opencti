import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { LayersClearOutlined, MoreVert } from '@mui/icons-material';
import Slide, { SlideProps } from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { RetentionLinesPaginationQuery$variables } from '@components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { RetentionLine_node$key } from '@components/settings/retention/__generated__/RetentionLine_node.graphql';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import RetentionPopover from './RetentionPopover';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { DataColumns } from '../../../../components/list_lines';

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
    color: theme.palette.grey[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 100,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

const RetentionLineFragment = graphql`
    fragment RetentionLine_node on RetentionRule {
        id
        name
        max_retention
        retention_unit
        last_execution_date
        remaining_count
        filters
        scope
    }
`;

interface RetentionLineProps {
  dataColumns: DataColumns;
  node: RetentionLine_node$key;
  paginationOptions: RetentionLinesPaginationQuery$variables;
}

export const RetentionLine: FunctionComponent<RetentionLineProps> = ({ dataColumns, node, paginationOptions }) => {
  const classes = useStyles();
  const { nsdt, n, t_i18n } = useFormatter();
  const data = useFragment(RetentionLineFragment, node);
  const filters = deserializeFilterGroupForFrontend(data.filters);
  let scopeColor = 'warning';
  let appliedOnContent = t_i18n('Everything');
  if (data.scope === 'file') {
    scopeColor = 'secondary';
    appliedOnContent = t_i18n('Global files');
  } else if (data.scope === 'workbench') {
    scopeColor = 'primary';
    appliedOnContent = t_i18n('Global workbenches');
  }
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <LayersClearOutlined/>
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.max_retention.width }}
            >
              {data.max_retention} {t_i18n(data.retention_unit)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.last_execution_date.width }}
            >
              {nsdt(data.last_execution_date)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.remaining_count.width }}
            >
              {n(data.remaining_count)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.scope.width }}
            >
              <Chip
                color={scopeColor as 'warning' | 'secondary' | 'primary'}
                classes={{ root: classes.chipInList }}
                label={t_i18n(data.scope.toUpperCase())}
                variant="outlined"
              />
            </div>
            {isFilterGroupNotEmpty(filters) ? (
              <FilterIconButton
                filters={filters}
                dataColumns={dataColumns}
                styleNumber={3}
                redirection
              />
            ) : (
              <div className={classes.bodyItem} style={{ width: dataColumns.filters.width }}>
                <span>{appliedOnContent}</span>
                {data.scope !== 'knowledge'
                  && <Tooltip
                    title={`${t_i18n('Files contained in')} ${t_i18n('Data')}/${t_i18n('Import')}`}
                     >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ position: 'absolute', marginLeft: 10 }}
                    />
                  </Tooltip>
                }
              </div>
            )}
          </div>
          }
      />
      <ListItemSecondaryAction>
        <RetentionPopover
          retentionRuleId={data.id}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const RetentionLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.max_retention.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>

            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.last_execution_date.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.remaining_count.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.scope.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.filters.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </div>
          </div>
          }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert/>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
