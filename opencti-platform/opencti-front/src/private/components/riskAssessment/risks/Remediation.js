import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import RemediationLines, {
  remediationLinesQuery,
} from './Remediation/RemediationLines';
import RemediationCreation from './Remediation/RemediationCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class Remediation extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      relationReversed: false,
      numberOfElements: { number: 0, symbol: '' },
    };
  }

  setNumberOfElements(numberOfElements) {
    this.setState({ numberOfElements });
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityId } = this.props;
    console.log('asfafdfsdgsRemediation', this.props.risk);
    const dataColumns = {
      name: {
        label: 'Title',
        width: '15%',
        isSortable: true,
      },
      type: {
        label: 'Response type',
        width: '15%',
        isSortable: false,
      },
      assetId: {
        label: 'Lifecycle',
        width: '15%',
        isSortable: false,
      },
      ipAddress: {
        label: 'Decision Maker',
        width: '15%',
        isSortable: true,
      },
      fqdn: {
        label: 'Start Date',
        width: '15%',
        isSortable: true,
      },
      os: {
        label: 'End Date',
        width: '12%',
        isSortable: true,
      },
      source: {
        label: 'Source',
        width: '12%',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        handleSearch={this.handleSearch.bind(this)}
        displayImport={true}
        secondaryAction={true}
        searchVariant="inDrawer2"
      >
        {/* <QR
          environment={QueryRendererDarkLight}
          query={remediationLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => ( */}
            <RemediationLines
              data={this.props.risk}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={this.props.risk === null}
              displayRelation={true}
              entityId={entityId}
              setNumberOfElements={this.setNumberOfElements.bind(this)}
            />
          {/* )}
        /> */}
      </ListLines>
    );
  }

  render() {
    const {
      view, sortBy, orderAsc, searchTerm, relationReversed,
    } = this.state;
    const { classes, t, entityId } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Remediation')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          {/* <RemediationCreation
            paginationOptions={paginationOptions}
            handleReverseRelation={this.handleReverseRelation.bind(this)}
            entityId={entityId}
            variant="inLine"
            isRelationReversed={relationReversed}
            targetStixDomainObjectTypes={[
              'Threat-Actor',
              'Intrusion-Set',
              'Campaign',
              'Incident',
              'Malware',
              'Tool',
              'Vulnerability',
              'Individual',
              'Organization',
              'Sector',
              'Region',
              'Country',
              'City',
              'Position',
            ]}
            targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
          /> */}
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        </Paper>
      </div>
    );
  }
}

Remediation.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Remediation);
