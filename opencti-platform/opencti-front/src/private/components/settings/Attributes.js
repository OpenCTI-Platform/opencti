import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../utils/ListParameters';
import inject18n from '../../../components/i18n';
import ListLines from '../../../components/list_lines/ListLines';
import TagsAttributesMenu from './TagsAttributesMenu';
import AttributesLines, {
  attributesLinesQuery,
} from './attributes/AttributesLines';
import AttributeCreation from './attributes/AttributeCreation';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
});

export const attributesSearchQuery = graphql`
  query AttributesSearchQuery($type: String!, $search: String, $first: Int) {
    attributes(type: $type, search: $search, first: $first) {
      edges {
        node {
          id
          value
        }
      }
    }
  }
`;

class Attributes extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      'view-attributes',
    );
    this.state = {
      sortBy: propOr('definition', 'sortBy', params),
      orderAsc: propOr(true, 'orderAsc', params),
      searchTerm: propOr('', 'searchTerm', params),
      view: propOr('lines', 'view', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      'view-attributes',
      this.state,
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc }, () => this.saveView());
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc, searchTerm } = this.state;
    const dataColumns = {
      value: {
        label: 'Value',
        width: '80%',
        isSortable: false,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={false}
        secondaryAction={true}
        keyword={searchTerm}
      >
        <QueryRenderer
          query={attributesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <AttributesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      classes,
      match: {
        params: { attributeLabel },
      },
    } = this.props;
    const { view, searchTerm } = this.state;
    const paginationOptions = {
      type: attributeLabel,
      search: searchTerm,
    };
    return (
      <div className={classes.container}>
        <TagsAttributesMenu />
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <AttributeCreation
          paginationOptions={paginationOptions}
          attributeType={attributeLabel}
        />
      </div>
    );
  }
}

Attributes.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  match: PropTypes.object,
  location: PropTypes.object,
};

export default compose(inject18n, withRouter, withStyles(styles))(Attributes);
