/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
import TextField from "@material-ui/core/TextField";
import Autocomplete from '@material-ui/lab/Autocomplete';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const searchTextFieldQuery = graphql`
  query SearchTextFieldQuery(
    $search: String
    $orderedBy: InformationTypeOrdering
    $orderMode: OrderingMode
  ) {
    informationTypes(
      search: $search
      orderedBy: $orderedBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          title
        }
      }
    }
  }
`;

const searchTextFieldIdQuery = graphql`
  query SearchTextFieldIdQuery($id: ID!) {
    informationType(id: $id) {
      id
      title
      created
      modified
    }
  }
`;

const styles = (theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

class SearchTextField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      openAutocomplete: false,
      products: [],
      productName: '',
      onSubmit: false,
      selectedProduct: {},
      displayCancel: false,
    };
  }

  searchProducts(event, value) {
    this.setState({ productName: value });
    if (event?.type === 'click' && value) {
      const selectedProductValue = this.state.products.filter(
        (product) => product.label === value,
      )[0];
      fetchQuery(searchTextFieldIdQuery, {
        id: selectedProductValue.value,
      }).toPromise()
        .then((data) => {
          this.setState({ selectedProduct: data.informationSystem });
        });
    }
  }

  handleSearchProducts(event, value) {
    fetchQuery(searchTextFieldQuery, {
      search: value === "" ? "" : value,
      orderedBy: 'name',
      orderMode: 'asc',
    })
      .toPromise()
      .then((data) => {
        const products = pipe(
          pathOr([], ['informationTypes', 'edges']),
          map((n) => ({
            label: n.node?.title,
            value: n.node?.id,
          })),
        )(data);
        this.setState({
          products: union(this.state.products, products),
        });
      })
      .catch((err) => {
        const ErrorResponse = err.res?.errors;
        this.setState({ error: ErrorResponse });
      });
  }

  render() {
    const {
      t, name, classes,
    } = this.props;
    const {
      selectedProduct,
      productName
    } = this.state;
    return (
      <div>
        <Field
          component={Autocomplete}
          name={name}
          size="small"
          loading={selectedProduct.name || false}
          loadingText="Searching..."
          className={classes.autocomplete}
          inputValue={productName}
          classes={{
            popupIndicatorOpen: classes.popupIndicator,
          }}
          noOptionsText={t('No available options')}
          popupIcon={<KeyboardArrowDownIcon />}
          options={this.state.products}
          getOptionLabel={(option) => (option.label ? option.label : option)}
          onInputChange={this.searchProducts.bind(this)}
          onFocus={this.handleSearchProducts.bind(this)}
          onChange={this.handleSearchProducts.bind(this)}
          selectOnFocus={true}
          autoHighlight={true}
          renderInput={(params) => (
            <TextField
              variant="outlined"
              {...params}
              inputProps={{
                ...params.inputProps,
                onKeyDown: (e) => {
                  if (e.key === 'Enter') {
                    e.stopPropagation();
                    this.handleSearchProducts();
                  }
                },
              }}
            />
          )}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(SearchTextField);
