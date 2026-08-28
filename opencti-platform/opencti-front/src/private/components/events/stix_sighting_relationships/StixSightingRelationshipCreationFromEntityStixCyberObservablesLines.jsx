import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, keys, groupBy, assoc } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import Typography from '@mui/material/Typography';
import { ExpandMore } from '@mui/icons-material';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    padding: '0 0 20px 0',
  },
  heading: {
    fontSize: theme.typography.pxToRem(15),
    flexBasis: '33.33%',
    flexShrink: 0,
  },
  secondaryHeading: {
    fontSize: theme.typography.pxToRem(15),
    color: theme.palette.text.secondary,
  },
  expansionPanelContent: {
    padding: 0,
  },
  list: {
    width: '100%',
  },
  listItem: {
    width: '100M',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const StixSightingRelationshipCreationFromEntityStixCyberObservablesLinesContainer = (props) => {
  const { t_i18n } = useFormatter();
  const [expandedPanels, setExpandedPanels] = useState({});
  const handleChangePanel = (panelKey, event, expanded) => {
    setExpandedPanels(assoc(panelKey, expanded, expandedPanels));
  };

  const isExpanded = (type, numberOfEntities, numberOfTypes) => {
    if (expandedPanels[type] !== undefined) {
      return expandedPanels[type];
    }
    if (numberOfEntities === 1) {
      return true;
    }
    return numberOfTypes === 1;
  };

  const { classes, data, handleSelect } = props;
  const stixCyberObservablesNodes = map(
    (n) => n.node,
    data.stixCyberObservables.edges,
  );
  const byType = groupBy(
    (stixCyberObservable) => stixCyberObservable.entity_type,
  );
  const stixCyberObservables = byType(stixCyberObservablesNodes);
  const stixCyberObservablesTypes = keys(stixCyberObservables);

  return (
    <div className={classes.container}>
      {stixCyberObservablesTypes.map((type) => (
        <Accordion
          key={type}
          expanded={isExpanded(
            type,
            stixCyberObservables[type].length,
            stixCyberObservablesTypes.length,
          )}
          onChange={handleChangePanel.bind(null, type)}
          elevation={3}
        >
          <AccordionSummary expandIcon={<ExpandMore />}>
            <Typography className={classes.heading}>
              {t_i18n(`entity_${type}`)}
            </Typography>
            <Typography className={classes.secondaryHeading}>
              {stixCyberObservables[type].length} {t_i18n('observable(s)')}
            </Typography>
          </AccordionSummary>
          <AccordionDetails classes={{ root: classes.expansionPanelContent }}>
            <List classes={{ root: classes.list }}>
              {stixCyberObservables[type].map((stixCyberObservable) => (
                <ListItemButton
                  key={stixCyberObservable.id}
                  classes={{ root: classes.menuItem }}
                  divider={true}
                  onClick={handleSelect.bind(null, stixCyberObservable)}
                >
                  <ListItemIcon>
                    <ItemIcon type={type} />
                  </ListItemIcon>
                  <ListItemText
                    primary={stixCyberObservable.observable_value}
                    secondary={truncate(stixCyberObservable.description, 100)}
                  />
                </ListItemButton>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      ))}
    </div>
  );
};

StixSightingRelationshipCreationFromEntityStixCyberObservablesLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
};

export const stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery = graphql`
  query StixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixSightingRelationshipCreationFromEntityStixCyberObservablesLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixSightingRelationshipCreationFromEntityStixCyberObservablesLines = createPaginationContainer(
  StixSightingRelationshipCreationFromEntityStixCyberObservablesLinesContainer,
  {
    data: graphql`
        fragment StixSightingRelationshipCreationFromEntityStixCyberObservablesLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          types: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: {
            type: "StixCyberObservablesOrdering"
            defaultValue: created_at
          }
          orderMode: { type: "OrderingMode", defaultValue: asc }
        ) {
          stixCyberObservables(
            search: $search
            types: $types
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_stixCyberObservables") {
            edges {
              node {
                id
                entity_type
                parent_types
                observable_value
              }
            }
          }
        }
      `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCyberObservables;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query:
        stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery,
  },
);

export default withStyles(styles)(StixSightingRelationshipCreationFromEntityStixCyberObservablesLines);
