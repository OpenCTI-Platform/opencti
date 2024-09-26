import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class OpinionDetailsComponent extends Component {
  render() {
    const { t, classes, opinion } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Entity details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Opinion')}
          </Typography>
          <MarkdownDisplay
            content={opinion.opinion}
            remarkGfmPlugin={true}
            commonmark={true}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Explanation')}
          </Typography>
          <MarkdownDisplay
            content={opinion.explanation}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </Paper>
      </div>
    );
  }
}

OpinionDetailsComponent.propTypes = {
  opinion: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const OpinionDetails = createFragmentContainer(OpinionDetailsComponent, {
  opinion: graphql`
    fragment OpinionDetails_opinion on Opinion {
      id
      opinion
      explanation
    }
  `,
});

export default compose(inject18n, withStyles(styles))(OpinionDetails);
