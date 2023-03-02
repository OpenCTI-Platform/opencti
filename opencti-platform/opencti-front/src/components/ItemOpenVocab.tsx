import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useFormatter } from './i18n';
import useVocabularyCategory from '../utils/hooks/useVocabularyCategory';
import { ItemOpenVocabQuery } from './__generated__/ItemOpenVocabQuery.graphql';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from './Loader';

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
  queryRef: PreloadedQuery<ItemOpenVocabQuery>;
}

const itemOpenVocabQuery = graphql`
  query ItemOpenVocabQuery($category: VocabularyCategory) {
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

const ItemOpenVocabComponent: FunctionComponent<
Omit<ItemOpenVocabProps, 'type'>
> = ({ value, small = true, queryRef }) => {
  const { t } = useFormatter();
  const { vocabularies } = usePreloadedQuery<ItemOpenVocabQuery>(
    itemOpenVocabQuery,
    queryRef,
  );
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
  const description = openVocab && openVocab.description
    ? openVocab.description
    : t('No description');
  const preStyle = small
    ? { margin: 0, paddingTop: 7, paddingBottom: 4 }
    : { marginTop: 7 };
  return (
    <span className={classes.container}>
      <pre style={preStyle}>{t(value)}</pre>
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

const ItemOpenVocab: FunctionComponent<Omit<ItemOpenVocabProps, 'queryRef'>> = (
  props,
) => {
  const { typeToCategory } = useVocabularyCategory();
  const queryRef = useQueryLoading<ItemOpenVocabQuery>(itemOpenVocabQuery, {
    category: typeToCategory(props.type),
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ItemOpenVocabComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default ItemOpenVocab;
