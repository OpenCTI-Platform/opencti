import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class OpinionDetailsComponent extends Component {
  render() {
    const { t, opinion } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Entity details')}>
          <Label>
            {t('Opinion')}
          </Label>
          <MarkdownDisplay
            content={opinion.opinion}
            remarkGfmPlugin={true}
            commonmark={true}
          />
          <Label sx={{ mt: 2 }}>
            {t('Explanation')}
          </Label>
          <MarkdownDisplay
            content={opinion.explanation}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </Card>
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
