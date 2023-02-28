/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
import TextField from "@material-ui/core/TextField";
import Autocomplete from '@material-ui/lab/Autocomplete';
import Avatar from '@material-ui/core/Avatar';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

const searchTextFieldQuery = graphql`
  query SearchTextFieldQuery(
    $search: String
    $filters: [ProductFiltering]
    $orderedBy: ProductOrdering
    $orderMode: OrderingMode
  ) {
    products(
      search: $search
      filters: $filters
      orderedBy: $orderedBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const searchTextFieldIdQuery = graphql`
  query SearchTextFieldIdQuery($id: ID!) {
    product(id: $id) {
      id
      created
      modified
      name
      vendor
      version
      cpe_identifier
      ... on SoftwareProduct {
        software_identifier
      }
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
          this.setState({ selectedProduct: data.product });
        });
    }
  }

  handleSearchProducts() {
    this.setState({ selectedProduct: { name: this.state.productName }, openAutocomplete: true });
    (this.state.productName.length > 2) && fetchQuery(searchTextFieldQuery, {
      search: this.state.productName,
      orderedBy: 'name',
      orderMode: 'asc',
      filters: [
        { key: 'object_type', values: ['software'] },
      ],
    })
      .toPromise()
      .then((data) => {
        const products = R.pipe(
          R.pathOr([], ['products', 'edges']),
          R.map((n) => ({
            label: n.node.name,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          products: R.union(this.state.products, products),
        });
      })
      .catch((err) => {
        const ErrorResponse = err.res?.errors;
        this.setState({ error: ErrorResponse });
      });
  }

  render() {
    const {
      t, name, style, classes, onChange, helpertext,
    } = this.props;
    const {
        open,
        selectedProduct,
        openAutocomplete,
        products,
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
          onKeyDown={this.handleSearchProducts.bind(this)}
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
