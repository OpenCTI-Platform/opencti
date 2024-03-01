import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql, useMutation } from 'react-relay';
import { assoc, groupBy, keys, map, pipe, pluck } from 'ramda';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { CheckCircle, ExpandMore } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipCreationForm, { stixCoreRelationshipBasicShape } from '../../common/stix_core_relationships/StixCoreRelationshipCreationForm';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useIsEnforceReference, useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { parse } from '../../../../utils/Time';

const useStyles = makeStyles((theme) => ({
  container: {
    padding: '20px 0 20px 0',
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
  icon: {
    color: theme.palette.primary.main,
  },
}));

export const indicatorMutationRelationAdd = graphql`
  mutation IndicatorAddObservablesLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput!
  ) {
    stixCoreRelationshipAdd(input: $input) {
      id
      from {
        ...IndicatorObservables_indicator
      }
    }
  }
`;

export const indicatorMutationRelationDelete = graphql`
  mutation IndicatorAddObservablesLinesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

const IndicatorAddObservablesLinesContainer = (props) => {
  const { indicator, indicatorObservables, data } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [commitRelationAdd] = useMutation(indicatorMutationRelationAdd);
  const [commitRelationDelete] = useMutation(indicatorMutationRelationDelete);

  const enableReferences = useIsEnforceReference('stix-core-relationship');
  const stixCoreRelationshipValidator = useSchemaCreationValidation('stix-core-relationship', stixCoreRelationshipBasicShape(t_i18n));
  const [expandedPanels, setExpandedPanels] = useState({});
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState(null);

  const handleOpenForm = () => {
    setShowForm(true);
  };
  const handleCloseForm = () => {
    setShowForm(false);
  };

  const toggleStixCyberObservable = (stixCyberObservable, alreadyAdded) => {
    const input = {
      fromId: indicator.id,
      toId: stixCyberObservable.id,
      relationship_type: 'based-on',
    };
    // Delete
    if (alreadyAdded) {
      commitRelationDelete({
        variables: { ...input },
        updater: (store) => deleteNodeFromEdge(store, 'observables', indicator.id, stixCyberObservable.id, { first: 25 }),
      });
      // Add with references
    } else if (enableReferences || !stixCoreRelationshipValidator.isValidSync(input)) {
      handleOpenForm();
      setSelected(stixCyberObservable);
      // Add
    } else {
      commitRelationAdd({
        variables: { input },
      });
    }
  };

  const createRelation = (values) => {
    const input = {
      ...values,
      fromId: indicator.id,
      toId: selected.id,
      relationship_type: 'based-on',
    };
    const finalValues = pipe(
      assoc('confidence', parseInt(input.confidence, 10)),
      assoc(
        'start_time',
        input.start_time ? parse(input.start_time).format() : null,
      ),
      assoc(
        'stop_time',
        input.stop_time ? parse(input.stop_time).format() : null,
      ),
      assoc('killChainPhases', pluck('value', input.killChainPhases)),
      assoc('createdBy', input.createdBy?.value),
      assoc('objectMarking', pluck('value', input.objectMarking)),
      assoc(
        'externalReferences',
        pluck('value', input.externalReferences),
      ),
    )(input);
    commitMutation({
      mutation: indicatorMutationRelationAdd,
      variables: { input: finalValues },
    });
    handleCloseForm();
  };

  const handleChangePanel = (panelKey, expanded) => {
    setExpandedPanels(assoc(panelKey, !expanded, expandedPanels));
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

  const indicatorObservablesIds = map((n) => n.node.id, indicatorObservables);
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
      {showForm
        ? <StixCoreRelationshipCreationForm
            fromEntities={[indicator]}
            toEntities={[selected]}
            relationshipTypes={['based-on']}
            onSubmit={createRelation}
            handleClose={handleCloseForm}
          />
        : <>
          {stixCyberObservablesTypes.length > 0 ? (
            stixCyberObservablesTypes.map((type) => {
              const expanded = isExpanded(
                type,
                stixCyberObservables[type].length,
                stixCyberObservablesTypes.length,
              );
              return (
                <Accordion
                  key={type}
                  expanded={expanded}
                  onChange={() => handleChangePanel(type, expanded)}
                  elevation={3}
                >
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography className={classes.heading}>
                      {t_i18n(`entity_${type}`)}
                    </Typography>
                    <Typography className={classes.secondaryHeading}>
                      {stixCyberObservables[type].length} {t_i18n('entitie(s)')}
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails
                    classes={{ root: classes.expansionPanelContent }}
                  >
                    <List classes={{ root: classes.list }}>
                      {stixCyberObservables[type].map((stixCyberObservable) => {
                        const alreadyAdded = indicatorObservablesIds.includes(
                          stixCyberObservable.id,
                        );
                        return (
                          <ListItem
                            key={stixCyberObservable.id}
                            classes={{ root: classes.menuItem }}
                            divider={true}
                            button={true}
                            onClick={() => toggleStixCyberObservable(stixCyberObservable, alreadyAdded)}
                          >
                            <ListItemIcon>
                              {alreadyAdded ? (
                                <CheckCircle classes={{ root: classes.icon }} />
                              ) : (
                                <ItemIcon type={type} />
                              )}
                            </ListItemIcon>
                            <ListItemText
                              primary={stixCyberObservable.observable_value}
                            />
                          </ListItem>
                        );
                      })}
                    </List>
                  </AccordionDetails>
                </Accordion>
              );
            })
          ) : (
            <div style={{ paddingLeft: 20 }}>
              {t_i18n('No entities were found for this search.')}
            </div>
          )}
        </>
        }
    </div>
  );
};

IndicatorAddObservablesLinesContainer.propTypes = {
  indicatorId: PropTypes.string,
  indicatorObservables: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const indicatorAddObservablesLinesQuery = graphql`
  query IndicatorAddObservablesLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...IndicatorAddObservablesLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const IndicatorAddObservablesLines = createPaginationContainer(
  IndicatorAddObservablesLinesContainer,
  {
    data: graphql`
      fragment IndicatorAddObservablesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }

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
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: indicatorAddObservablesLinesQuery,
  },
);

export default IndicatorAddObservablesLines;
