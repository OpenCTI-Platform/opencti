import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useFormatter } from './i18n';
import useVocabularyCategory from '../utils/hooks/useVocabularyCategory';
import { ItemOpenVocabQuery } from './__generated__/ItemOpenVocabQuery.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: 0,
    display: 'flex',
  },
  icon: {
    margin: '15px 0 0 10px',
  },
  smallIcon: {
    margin: '5px 0 0 10px',
  },
}));

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small: boolean;
}

const itemOpenVocabQuery = graphql`
  query ItemOpenVocabQuery(
    $category: VocabularyCategory
  ) {
    vocabularies(category: $category) {
      edges {
        node {
          name
          description
        }
      }
    }
  }
`;

const ItemOpenVocab: FunctionComponent<ItemOpenVocabProps> = ({
  type,
  value,
  small = true,
}) => {
  const { t } = useFormatter();

  const { typeToCategory } = useVocabularyCategory();
  const { vocabularies } = useLazyLoadQuery<ItemOpenVocabQuery>(itemOpenVocabQuery, { category: typeToCategory(type) });
  const openVocabList = (vocabularies?.edges ?? []).map(({ node }) => node);

  const classes = useStyles();
  if (!value) {
    return (
      <span className={classes.container}>
        <pre style={{ margin: 0, paddingTop: 7, paddingBottom: 4 }}>
          {t('Unknown')}
        </pre>
        <Tooltip title={t('No description')}>
          <InformationOutline
            className={small ? classes.smallIcon : classes.icon}
            fontSize="small"
            color="secondary"
          />
        </Tooltip>
      </span>
    );
  }
  const openVocab = R.head(openVocabList.filter((n) => n.name === value));
  const description = openVocab && openVocab.description ? openVocab.description : t('No description');
  const preStyle = small
    ? { margin: 0, paddingTop: 7, paddingBottom: 4 }
    : { marginTop: 7 };
  return (
    <span className={classes.container}>
      <pre style={preStyle}>{value}</pre>
      <Tooltip title={t(description)}>
        <InformationOutline
          className={small ? classes.smallIcon : classes.icon}
          fontSize="small"
          color="secondary"
        />
      </Tooltip>
    </span>
  );
};

export default ItemOpenVocab;
