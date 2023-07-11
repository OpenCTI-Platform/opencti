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
  inlineIcon: {
    margin: '5px 0 0 2px',
  },
  pre: {
    marginTop: '7px',
  },
  smallPre: {
    margin: 0,
    paddingTop: '7px',
    paddingBottom: '4px',
  },
  inlinePre: {
    margin: 0,
    padding: '5px',
  },
}));

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small: boolean;
  inline?: boolean;
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

const ItemOpenVocabDummy = ({ small }: { small: boolean }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <span className={classes.container}>
      <pre style={{ margin: 0, paddingTop: 7, paddingBottom: 4 }}>
        {t('Unknown')}
      </pre>
      <Tooltip title={t('No description')}>
        <InformationOutline
          className={small ? classes.smallIcon : classes.icon}
          fontSize="small"
          color="disabled"
        />
      </Tooltip>
    </span>
  );
};
const ItemOpenVocabComponent: FunctionComponent<
Omit<ItemOpenVocabProps, 'type'>
> = ({ value, small = true, inline = false, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { vocabularies } = usePreloadedQuery<ItemOpenVocabQuery>(
    itemOpenVocabQuery,
    queryRef,
  );
  const openVocabList = (vocabularies?.edges ?? []).map(({ node }) => node);
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
  let preClass = small ? classes.smallPre : classes.pre;
  let iconClass = small ? classes.smallIcon : classes.icon;
  if (inline) {
    iconClass = classes.inlineIcon;
    preClass = classes.inlinePre;
  }
  return (
    <span className={classes.container}>
      <pre className={preClass}>{value}</pre>
      <Tooltip title={t(description)}>
        <InformationOutline
          className={iconClass}
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
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<ItemOpenVocabDummy small={props.small} />}>
          <ItemOpenVocabComponent {...props} queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default ItemOpenVocab;
