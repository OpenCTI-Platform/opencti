/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { Field, useField } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import KeyboardArrowDownIcon from '@material-ui/icons/KeyboardArrowDown';
import TextField from "@material-ui/core/TextField";
import Autocomplete from '@material-ui/lab/Autocomplete';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';


const searchTextFieldQuery = graphql`
  query SearchTextFieldQuery(
    $orderedBy: InformationTypeOrdering
    $orderMode: OrderingMode
  ) {
    informationTypes(
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
      entity_type
      created
      modified
      title
      description
      categorizations {
        id
        entity_type
        system
        information_type {
          id
          entity_type
          identifier
          category
        }
      }
      confidentiality_impact {
        id
        entity_type
        base_impact
        explanation
        recommendation
        selected_impact
        adjustment_justification
      }
      integrity_impact {
        id
        entity_type
        base_impact
        explanation
        recommendation
        selected_impact
        adjustment_justification      
      }
      availability_impact {
        id
        entity_type
        base_impact
        explanation
        recommendation
        selected_impact
        adjustment_justification      
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

  searchProduct(event, value) {
    this.setState({ productName: value });
    this.props.setFieldValue(this.props.name, value);
    if (event?.type === 'click' && value) {
      const selectedProductValue = this.state.products.filter(
        (product) => product.label === value,
      )[0];
      fetchQuery(searchTextFieldIdQuery, {
        id: selectedProductValue.value,
      }).toPromise()
        .then((data) => {
          this.setState({ selectedProduct: data.informationType });
          this.props.handleSearchTextField(data.informationType, this.props.setFieldValue);
        });
    }
  }

  handleSearchProducts() {
    fetchQuery(searchTextFieldQuery, {
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
      t, name, classes, errors,
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
          loading={Boolean(selectedProduct?.title)}
          freeSolo
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
          onInputChange={this.searchProduct.bind(this)}
          onFocus={this.handleSearchProducts.bind(this)}
          onChange={this.handleSearchProducts.bind(this)}
          selectOnFocus={true}
          autoHighlight={true}
          renderInput={(params) => (
            <TextField
              variant="outlined"
              {...params}
              error={Boolean(errors)}
              helperText={Boolean(errors) ? 'This field is required' : ''}
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
