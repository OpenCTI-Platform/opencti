import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import CyioNoteEditionOverview from './CyioNoteEditionOverview';

const styles = (theme) => ({
  header: {
    // backgroundColor: theme.palette.navAlt.backgroundHeader,
    // color: theme.palette.navAlt.backgroundHeaderText,
    padding: '15px 0 0 20px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

export const cyioNoteEditionQuery = graphql`
  query CyioNoteEditionContainerQuery($id: ID!) {
    cyioNote(id: $id) {
      ...CyioNoteEditionContainer_note
    }
  }
`;

class CyioNoteEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const {
      t, classes, handleClose, note, refreshQuery,
    } = this.props;
    const { editContext } = note;
    return (
      <div>
        <div className={classes.header}>
          {/* <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton> */}
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Note')}
          </Typography>
          {/* <SubscriptionAvatars context={editContext} /> */}
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <CyioNoteEditionOverview
            note={this.props.note}
            refreshQuery={refreshQuery}
            context={editContext}
            handleClose={handleClose.bind(this)}
          />
        </div>
      </div>
    );
  }
}

CyioNoteEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  note: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const CyioNoteEditionFragment = createFragmentContainer(CyioNoteEditionContainer, {
  note: graphql`
    fragment CyioNoteEditionContainer_note on CyioNote {
      id
      ...CyioNoteEditionOverview_note
      # editContext {
      #   name
      #   focusOn
      # }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioNoteEditionFragment);
