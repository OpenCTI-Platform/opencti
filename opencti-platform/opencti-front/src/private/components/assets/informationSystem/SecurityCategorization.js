import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import SecurityCategorizationField from '../../common/form/SecurityCategorizationField';

const styles = () => ({
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

const securityCategorizationCategoryQuery = graphql`
query SecurityCategorizationCategoryQuery($id: ID!) {
  getCatalogCategories(id: $id)
}
`;

const securityCategorizationInformationTypeQuery = graphql`
query SecurityCategorizationInformationTypeQuery(
  $id: ID!,
  $categoryName: String!
) {
  getCategoryMembers(id: $id, categoryName: $categoryName) {
    id
    entity_type
    identifier
    category
    system
    title
    display_name
    confidentiality_impact {
      id
      base_impact
      explanation
      recommendation
    }
    integrity_impact {
      id
      base_impact
      explanation
      recommendation
    }
    availability_impact {
      id
      base_impact
      explanation
      recommendation
    }
  }
}
`;

class SecurityCategorization extends Component {
  constructor(props) {
    super(props);
    this.state = {
      selectedCategorization: '',
      categoryField: [],
      informationTypeField: [],
    };
  }

  componentDidMount() {
    const { values } = this.props;
    if (values.catalog) {
      this.handleCategoryChange('catalog', values.catalog);
    }
    if (values.system) {
      this.handleCategoryChange('system', values.system);
    }
  }

  handleCategoryChange(name, value) {
    if (name === 'catalog') {
      fetchQuery(securityCategorizationCategoryQuery, {
        id: value,
      })
        .toPromise()
        .then((data) => {
          this.setState({
            categoryField: data.getCatalogCategories,
            selectedCategorization: value,
          });
        });
    }
    if (name === 'system') {
      fetchQuery(securityCategorizationInformationTypeQuery, {
        id: this.state.selectedCategorization || this.props.values.catalog,
        categoryName: value,
      })
        .toPromise()
        .then((data) => {
          this.setState({ informationTypeField: data.getCategoryMembers });
        });
    }
    if (name === 'information_type') {
      const filteredInfo = this.state.informationTypeField.filter((info) => info.id === value);
      this.props.handleInformationType(filteredInfo[0], this.props.setFieldValue);
    }
  }

  render() {
    const { t, classes, values } = this.props;
    return (
      <>
        <Grid item={true} xs={4}>
          <div className={classes.textBase}>
            <Typography
              variant='h3'
              color='textSecondary'
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('Categorization System')}
            </Typography>
            <Tooltip
              title={t(
                'Categorization System Identifies the information type identification system used',
              )}
            >
              <Information style={{ marginLeft: '5px' }} fontSize='inherit' color='disabled' />
            </Tooltip>
          </div>
          <div className='clearfix' />
          <SecurityCategorizationField
            values={values}
            fullWidth={true}
            variant='outlined'
            name='catalog'
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            onChange={this.handleCategoryChange.bind(this)}
          />
        </Grid>
        <Grid item={true} xs={4}>
          <div className={classes.textBase}>
            <Typography
              variant='h3'
              color='textSecondary'
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('Category')}
            </Typography>
            <Tooltip title={t('Category Identifies a categorization of an information type.')}>
              <Information style={{ marginLeft: '5px' }} fontSize='inherit' color='disabled' />
            </Tooltip>
          </div>
          <div className='clearfix' />
          <SecurityCategorizationField
            values={values}
            name='system'
            fullWidth={true}
            variant='outlined'
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            categoryField={this.state.categoryField}
            onChange={this.handleCategoryChange.bind(this)}
          />
        </Grid>
        <Grid item={true} xs={4}>
          <div className={classes.textBase}>
            <Typography
              variant='h3'
              color='textSecondary'
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('Information Type')}
            </Typography>
            <Tooltip
              title={t(
                'Information Type Identifies a unique identifier, qualified by the given identification system used, for an information type. This is typically composed of the identifier and the title.',
              )}
            >
              <Information style={{ marginLeft: '5px' }} fontSize='inherit' color='disabled' />
            </Tooltip>
          </div>
          <div className='clearfix' />
          <SecurityCategorizationField
            values={values}
            fullWidth={true}
            variant='outlined'
            name='information_type'
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            onChange={this.handleCategoryChange.bind(this)}
            informationTypeField={this.state.informationTypeField}
          />
        </Grid>
      </>
    );
  }
}

SecurityCategorization.propTypes = {
  t: PropTypes.func,
  values: PropTypes.object,
  classes: PropTypes.object,
  handleInformationType: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(SecurityCategorization);
