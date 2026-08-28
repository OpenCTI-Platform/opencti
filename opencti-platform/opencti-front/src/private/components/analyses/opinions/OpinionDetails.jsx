import React from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

const OpinionDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { opinion } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Entity details')}>
        <Label>
          {t_i18n('Opinion')}
        </Label>
        <MarkdownDisplay
          content={opinion.opinion}
          remarkGfmPlugin={true}
          commonmark={true}
        />
        <Label sx={{ mt: 2 }}>
          {t_i18n('Explanation')}
        </Label>
        <MarkdownDisplay
          content={opinion.explanation}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </Card>
    </div>
  );
};

OpinionDetailsComponent.propTypes = {
  opinion: PropTypes.object,
  classes: PropTypes.object,
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

export default compose(withStyles(styles))(OpinionDetails);
