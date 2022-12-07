/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import DataSourceDetails from './DataSourceDetails';
import DataSourcesPopover from './DataSourcesPopover';
import DataSourcesDeletion from './DataSourcesDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import DataSourceEditionContainer from './DataSourceEditionContainer';
import DataSourcesCreation from './DataSourcesCreation';

const styles = () => ({
  container: {
    margin: '0 0 40px 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class DataSourceComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleDataSourceCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      classes,
      dataSource,
      history,
      refreshQuery,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            history={history}
            name={dataSource.name}
            cyioDomainObject={dataSource}
            goBack='/data/data source'
            PopoverComponent={<DataSourcesPopover />}
            OperationsComponent={<DataSourcesDeletion />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleDataSourceCreation.bind(this)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <DataSourceDetails dataSource={dataSource} history={history} refreshQuery={refreshQuery} />
            </Grid>
          </Grid>
        </div>
        <DataSourcesCreation
          openDataCreation={this.state.openDataCreation}
          handleDataSourceCreation={this.handleDataSourceCreation.bind(this)}
          history={history}
        />
        <DataSourceEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          dataSource={dataSource}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

DataSourceComponent.propTypes = {
  dataSource: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityLocation = createFragmentContainer(DataSourceComponent, {
  dataSource: graphql`
    fragment DataSource_data on DataSource {
      __typename
      id
      created
      modified
      name
      description
      ...DataSourceDetails_data
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityLocation);
