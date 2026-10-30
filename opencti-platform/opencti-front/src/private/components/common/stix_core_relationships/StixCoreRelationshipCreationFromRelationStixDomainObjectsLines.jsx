import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, keys, groupBy, assoc } from 'ramda';
import { styled } from '@mui/material/styles';
import Accordion from '@mui/material/Accordion';
import AccordionDetails from '@mui/material/AccordionDetails';
import AccordionSummary from '@mui/material/AccordionSummary';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { ExpandMore } from '@mui/icons-material';
import { ListItemButton } from '@mui/material';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../stix_core_objects/StixCoreObjectLabels';
import { getMainRepresentative } from 'src/utils/defaultRepresentatives';

const Container = styled('div')({
  padding: '20px 0 0 0',
});

const Heading = styled(Typography)(({ theme }) => ({
  fontSize: theme.typography.pxToRem(15),
  flexBasis: '33.33%',
  flexShrink: 0,
}));

const SecondaryHeading = styled(Typography)(({ theme }) => ({
  fontSize: theme.typography.pxToRem(15),
  color: theme.palette.text.secondary,
}));

const Item = styled(ListItemButton)(({ theme }) => ({
  minHeight: 48,
  paddingTop: theme.spacing(0.5),
  paddingBottom: theme.spacing(0.5),
}));

// The icon keeps the summary title's left edge; only the name track moves in.
const ItemIconContainer = styled(ListItemIcon)(({ theme }) => ({
  minWidth: 'auto',
  marginRight: theme.spacing(2),
}));

// Shrink-to-fit, so the labels follow the name instead of a far column.
const ItemText = styled(ListItemText)(({ theme }) => ({
  flex: '0 1 auto',
  minWidth: 0,
  margin: 0,
  marginRight: theme.spacing(2),
  '& .MuiListItemText-primary, & .MuiListItemText-secondary': {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
}));

// Without a shrinkable track of their own the labels win the row and the
// name is the one that gets cut; they fold to `+N` instead.
const ItemLabels = styled('div')({
  flex: '0 1 auto',
  minWidth: 0,
});

const NoResult = styled('div')(({ theme }) => ({
  top: 95,
  left: 16,
  right: 0,
  position: 'absolute',
  color: theme.palette.text.primary,
  fontSize: 15,
  zIndex: -5,
}));

class StixCoreRelationshipCreationFromRelationLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedPanels: {} };
  }

  handleChangePanel(panelKey, event, expanded) {
    this.setState({
      expandedPanels: assoc(panelKey, expanded, this.state.expandedPanels),
    });
  }

  isExpanded(type, numberOfEntities, numberOfTypes) {
    if (this.state.expandedPanels[type] !== undefined) {
      return this.state.expandedPanels[type];
    }
    if (numberOfEntities === 1) {
      return true;
    }
    return numberOfTypes === 1;
  }

  render() {
    const { t, data, handleSelect } = this.props;
    const stixDomainObjectsNodes = map(
      (n) => n.node,
      data.stixDomainObjects.edges,
    );
    const byType = groupBy((stixDomainObject) => stixDomainObject.entity_type);
    const stixDomainObjects = byType(stixDomainObjectsNodes);
    const stixDomainObjectsTypes = keys(stixDomainObjects);

    return (
      <Container>
        {stixDomainObjectsTypes.length > 0 ? (
          stixDomainObjectsTypes.map((type) => {
            return (
              <Accordion
                key={type}
                expanded={this.isExpanded(
                  type,
                  stixDomainObjects[type].length,
                  stixDomainObjectsTypes.length,
                )}
                onChange={this.handleChangePanel.bind(this, type)}
                // `disableGutters`: MUI otherwise margins every expanded panel, opening gaps.
                elevation={0}
                disableGutters
                sx={{ backgroundColor: 'var(--bg-input-default)' }}
              >
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Heading>
                    {t(`entity_${type}`)}
                  </Heading>
                  <SecondaryHeading>
                    {stixDomainObjects[type].length} {t('entitie(s)')}
                  </SecondaryHeading>
                </AccordionSummary>
                <AccordionDetails sx={{ padding: 0 }}>
                  <List sx={{ width: '100%' }}>
                    {stixDomainObjects[type].map((stixDomainObject) => (
                      <Item
                        key={stixDomainObject.id}
                        divider={true}
                        onClick={handleSelect.bind(this, stixDomainObject)}
                      >
                        <ItemIconContainer>
                          <ItemIcon type={type} />
                        </ItemIconContainer>
                        <ItemText
                          primary={truncate(getMainRepresentative(stixDomainObject), 100)}
                          secondary={truncate(stixDomainObject.description, 100)}
                        />
                        <ItemLabels>
                          <StixCoreObjectLabels
                            variant="inList"
                            labels={stixDomainObject.objectLabel}
                            revoked={stixDomainObject.revoked}
                            defaultValueIfEmpty=""
                          />
                        </ItemLabels>
                      </Item>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            );
          })
        ) : (
          <NoResult>
            {t('No entities were found for this search.')}
          </NoResult>
        )}
      </Container>
    );
  }
}

StixCoreRelationshipCreationFromRelationLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreRelationshipCreationFromRelationStixDomainObjectsLinesQuery = graphql`
  query StixCoreRelationshipCreationFromRelationStixDomainObjectsLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCoreRelationshipCreationFromRelationStixDomainObjectsLines_data
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

const StixCoreRelationshipCreationFromRelationStixDomainObjectsLines = createPaginationContainer(
  StixCoreRelationshipCreationFromRelationLinesContainer,
  {
    data: graphql`
        fragment StixCoreRelationshipCreationFromRelationStixDomainObjectsLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          types: { type: "[String]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
          orderMode: { type: "OrderingMode", defaultValue: asc }
        ) {
          stixDomainObjects(
            search: $search
            types: $types
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
          ) @connection(key: "Pagination_stixDomainObjects") {
            edges {
              node {
                id
                entity_type
                parent_types
                revoked
                objectLabel {
                  id
                  value
                  color
                }
                ... on AttackPattern {
                  name
                  description
                }
                ... on Note {
                  attribute_abstract
                  content
                }
                ... on Opinion {
                  opinion
                }
                ... on Report {
                  name
                }
                ... on Grouping {
                  name
                }
                ... on Campaign {
                  name
                  description
                }
                ... on CourseOfAction {
                  name
                  description
                }
                ... on Individual {
                  name
                  description
                }
                ... on Organization {
                  name
                  description
                }
                ... on Sector {
                  name
                  description
                }
                ... on System {
                  name
                  description
                }
                ... on Indicator {
                  name
                  description
                }
                ... on Infrastructure {
                  name
                  description
                }
                ... on IntrusionSet {
                  name
                  description
                }
                ... on Position {
                  name
                  description
                }
                ... on City {
                  name
                  description
                }
                ... on AdministrativeArea {
                  name
                  description
                }
                ... on Country {
                  name
                  description
                }
                ... on Region {
                  name
                  description
                }
                ... on Malware {
                  name
                  description
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                  description
                }
                ... on Tool {
                  name
                  description
                }
                ... on Vulnerability {
                  name
                  description
                }
                ... on Incident {
                  name
                  description
                }
                ... on Event {
                  name
                  description
                }
                ... on Channel {
                  name
                  description
                }
                ... on Narrative {
                  name
                  description
                }
                ... on Language {
                  name
                }
                ... on DataComponent {
                  name
                }
                ... on DataSource {
                  name
                }
                ... on Case {
                  name
                }
              }
            }
          }
        }
      `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixDomainObjects;
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
        stixCoreRelationshipCreationFromRelationStixDomainObjectsLinesQuery,
  },
);

export default inject18n(StixCoreRelationshipCreationFromRelationStixDomainObjectsLines);
