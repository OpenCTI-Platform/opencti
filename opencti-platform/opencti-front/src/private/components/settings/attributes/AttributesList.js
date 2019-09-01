import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import List from '@material-ui/core/List';
import { withStyles } from '@material-ui/core/styles';
import { compose, pathOr } from 'ramda';
import inject18n from '../../../../components/i18n';
import AttributeLine from './AttributeLine';

const styles = () => ({
  list: {
    padding: 0,
  },
});

class AttributesList extends Component {
  render() {
    const { classes } = this.props;
    const attributes = pathOr([], ['attributes', 'edges'], this.props.data);
    return (
      <List classes={{ root: classes.list }}>
        {attributes.map((attributeEge) => {
          const attribute = attributeEge.node;
          return (
            <AttributeLine
              key={attribute.id}
              attribute={attribute}
              paginationOptions={this.props.paginationOptions}
            />
          );
        })}
      </List>
    );
  }
}

AttributesList.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  data: PropTypes.object,
};

export const attributesListQuery = graphql`
  query AttributesListQuery($type: String!, $count: Int!) {
    ...AttributesList_data @arguments(type: $type, count: $count)
  }
`;

export const attributesQuery = graphql`
  query AttributesListAttributesQuery($type: String!) {
    attributes(type: $type) {
      edges {
        node {
          id
          type
          value
        }
      }
    }
  }
`;

const AttributesListFragment = createFragmentContainer(
  AttributesList,
  {
    data: graphql`
      fragment AttributesList_data on Query
        @argumentDefinitions(
          type: { type: "String!" }
          count: { type: "Int", defaultValue: 5000 }
        ) {
        attributes(first: $count, type: $type)
          @connection(key: "Pagination_attributes") {
          edges {
            node {
              id
              ...AttributeLine_attribute
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.attributes;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: attributesListQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AttributesListFragment);
