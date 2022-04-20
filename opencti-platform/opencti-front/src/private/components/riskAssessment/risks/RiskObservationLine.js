import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
// import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import LinkIcon from '@material-ui/icons/Link';
import Divider from '@material-ui/core/Divider';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import ListItemText from '@material-ui/core/ListItemText';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import { ExpandMoreOutlined, ExpandLessOutlined } from '@material-ui/icons';
import Slide from '@material-ui/core/Slide';
import { commitMutation as CM, createPaginationContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
// import { commitMutation } from '../../../../relay/environment';
import RiskObservationPopover from './RiskObservationPopover';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: 0,
    position: 'relative',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskObservationLineContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      displayExternalRefID: false,
      expanded: false,
    };
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  handleOpenDialog(externalReferenceEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: externalReferenceEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeExternalReference(this.state.removeExternalReference);
  }

  handleOpenExternalLink(url) {
    this.setState({ displayExternalLink: true, externalLink: url });
  }

  handleCloseExternalLink() {
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleBrowseExternalLink() {
    window.open(this.state.externalLink, '_blank');
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleToggleDetails() {
    this.setState({ displayExternalRefID: !this.state.displayExternalRefID });
  }

  render() {
    const {
      t, classes, cyioCoreObjectId, risk, fd, relay, fldt,
    } = this.props;
    const RelatedObservations = R.pathOr([], ['related_observations', 'edges'], risk);
    return (
      <div>
        {RelatedObservations.map((observation) => (
          <List key={observation.node.id} style={{ marginBottom: 0, padding: '0 12px 12px 12px' }}>
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '90% 10%', marginBottom: '10px' }}>
                <div style={{ padding: '10px 0 0 18px' }}>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    style={{ float: 'left' }}
                  >
                    <strong style={{ color: '#00bcd4' }}>
                      {observation.node.name && t(observation.node.name)}
                    </strong>
                    &nbsp; added an Observation on &nbsp;
                    <strong style={{ color: 'white' }}>
                      {observation.node.collected && fldt(observation.node.collected)}
                    </strong>
                  </Typography>
                  <br /> <br />
                  <Typography
                    variant="h2"
                    style={{ color: 'white' }}
                  >
                    {observation.node.description && t(observation.node.description)}
                  </Typography>
                </div>
                <div style={{ marginTop: '12px' }}>
                  <RiskObservationPopover data={observation.node} />
                </div>
              </div>
              <Divider variant="middle" light={true} />
            </div>
          </List>
        ))}
      </div>
    );
  }
}

RiskObservationLineContainer.propTypes = {
  risk: PropTypes.object,
  cyioCoreObjectId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fd: PropTypes.func,
  relay: PropTypes.object,
};

export const riskObservationLineQuery = graphql`
  query RiskObservationLinePaginationQuery($id: ID!, $first: Int, $offset: Int) {
    risk(id: $id){
      id
      ...RiskObservationLine_risk
      @arguments(
        count: $first
        offset: $offset
      )
    }
  }
`;

export const RiskObservationLineContainerComponent = createPaginationContainer(
  RiskObservationLineContainer,
  {
    risk: graphql`
      fragment RiskObservationLine_risk on Risk
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 5 }
        offset: { type: "Int", defaultValue: 0 }
      ) {
        related_observations (
          first: $count,
          offset: $offset
          ) @connection(key: "Pagination_related_observations"){
          edges {
            node {
              id
              entity_type
              collected
              description
              name
              description
              ...RiskObservationPopover_risk
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.related_observations;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        first: fragmentVariables.first,
        offset: fragmentVariables.offset,
        count,
        cursor,
      };
    },
    query: riskObservationLineQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RiskObservationLineContainerComponent);
