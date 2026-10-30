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

const Container = styled('div')({
  padding: '0 0 20px 0',
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

const PanelContent = styled(AccordionDetails)({
  padding: 0,
});

const ObservableList = styled(List)({
  width: '100%',
});

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

const ItemText = styled(ListItemText)({
  flex: '0 1 auto',
  minWidth: 0,
  margin: 0,
  '& .MuiListItemText-primary, & .MuiListItemText-secondary': {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
});

class StixCoreRelationshipCreationFromRelationStixCyberObservablesLinesContainer extends Component {
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
      <Container>
        {stixCyberObservablesTypes.map((type) => (
          <Accordion
            key={type}
            expanded={this.isExpanded(
              type,
              stixCyberObservables[type].length,
              stixCyberObservablesTypes.length,
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
                {stixCyberObservables[type].length} {t('observable(s)')}
              </SecondaryHeading>
            </AccordionSummary>
            <PanelContent>
              <ObservableList>
                {stixCyberObservables[type].map((stixCyberObservable) => (
                  <Item
                    key={stixCyberObservable.id}
                    divider={true}
                    onClick={handleSelect.bind(this, stixCyberObservable)}
                  >
                    <ItemIconContainer>
                      <ItemIcon type={type} />
                    </ItemIconContainer>
                    <ItemText
                      primary={stixCyberObservable.observable_value}
                      secondary={truncate(stixCyberObservable.description, 100)}
                    />
                  </Item>
                ))}
              </ObservableList>
            </PanelContent>
          </Accordion>
        ))}
      </Container>
    );
  }
}

StixCoreRelationshipCreationFromRelationStixCyberObservablesLinesContainer.propTypes = {
  handleSelect: PropTypes.func,
  data: PropTypes.object,
  limit: PropTypes.number,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreRelationshipCreationFromRelationStixCyberObservablesLinesQuery = graphql`
  query StixCoreRelationshipCreationFromRelationStixCyberObservablesLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCoreRelationshipCreationFromRelationStixCyberObservablesLines_data
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

const StixCoreRelationshipCreationFromRelationStixCyberObservablesLines = createPaginationContainer(
  StixCoreRelationshipCreationFromRelationStixCyberObservablesLinesContainer,
  {
    data: graphql`
        fragment StixCoreRelationshipCreationFromRelationStixCyberObservablesLines_data on Query
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
        stixCoreRelationshipCreationFromRelationStixCyberObservablesLinesQuery,
  },
);

export default inject18n(StixCoreRelationshipCreationFromRelationStixCyberObservablesLines);
