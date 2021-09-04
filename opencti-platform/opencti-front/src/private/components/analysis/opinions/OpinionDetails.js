import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
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
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Opinion')}
          </Typography>
          <Markdown remarkPlugins={[remarkGfm]} className="markdown">
            {opinion.opinion}
          </Markdown>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Explanation')}
          </Typography>
          <Markdown remarkPlugins={[remarkGfm]} className="markdown">
            {opinion.explanation}
          </Markdown>
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
