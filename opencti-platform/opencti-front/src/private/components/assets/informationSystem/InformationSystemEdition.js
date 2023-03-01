import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { toastGenericError } from '../../../../utils/bakedToast';
import InformationSystemEditionContainer from './InformationSystemEditionContainer';

const styles = () => ({
  container: {
    margin: 0,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const informationSystemEditionQuery = graphql`
  query InformationSystemEditionQuery($id: ID!) {
    informationSystem(id: $id) {
      __typename
      id
      short_name
      system_name
      description
      deployment_model
      cloud_service_model
      identity_assurance_level
      federation_assurance_level
      authenticator_assurance_level
    }
  }
`;

class InformationSystemEdition extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
    };
  }

  render() {
    const {
      classes, displayEdit, handleDisplayEdit, history, informationSystemId,
    } = this.props;
    return (
      <div className={classes.container}>
        <QueryRenderer
          query={informationSystemEditionQuery}
          variables={{ id: informationSystemId }}
          render={({ error, props, retry }) => {
            if (error) {
              toastGenericError('Failed to edit Task');
            }
            if (props) {
              return (
                <InformationSystemEditionContainer
                  displayEdit={displayEdit}
                  history={history}
                  informationSystem={props.informationSystem}
                  refreshQuery={retry}
                  handleDisplayEdit={handleDisplayEdit}
                />
              );
            }
            return <></>;
          }}
        />
      </div>
    );
  }
}

InformationSystemEdition.propTypes = {
  informationSystemId: PropTypes.string,
  displayEdit: PropTypes.bool,
  handleDisplayEdit: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(InformationSystemEdition);
