import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useFormatter } from './i18n';
import { Theme } from './Theme';
import useVocabularyCategory from '../utils/hooks/useVocabularyCategory';
import { ItemOpenVocabQuery } from './__generated__/ItemOpenVocabQuery.graphql';
import useQueryLoading from '../utils/hooks/useQueryLoading';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: 0,
    display: 'flex',
  },
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: '0',
    width: 120,
    height: 'auto',
    color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
    borderColor: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
    backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, .1)' : 'rgba(0, 0, 0, .1)',
    '& .MuiChip-label': {
      whiteSpace: 'normal',
      padding: '4px 6px',
    },
  },
  icon: {
    margin: '15px 0 0 10px',
  },
  smallIcon: {
    margin: '5px 0 0 10px',
  },
  pre: {
    marginTop: '7px',
  },
  smallPre: {
    margin: 0,
    paddingTop: '7px',
    paddingBottom: '4px',
  },
}));

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small?: boolean;
  chipDisplay?: boolean;
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

const ItemOpenVocabDummy = ({ small = true, chipDisplay = false }: { small?: boolean, chipDisplay?: boolean }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  if (chipDisplay) {
    return (
      <Tooltip title={t('No description')}>
        <Chip
          classes={{ root: classes.chip }}
          label={t('Unknown')}
        />
      </Tooltip>
    );
  }
  return (
    <span className={classes.container}>
      <pre className={small ? classes.smallPre : classes.pre}>
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
> = ({ value, small = true, chipDisplay = false, queryRef }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { vocabularies } = usePreloadedQuery<ItemOpenVocabQuery>(
    itemOpenVocabQuery,
    queryRef,
  );
  let description = t('No description');
  if (value) {
    const openVocabList = (vocabularies?.edges ?? []).map(({ node }) => node);
    const openVocab = openVocabList.find((n) => n.name === value);
    description = openVocab?.description ? openVocab.description : t('No description');
  }
  if (chipDisplay) {
    return (
      <Tooltip title={t(description)}>
        <Chip
          classes={{ root: classes.chip }}
          label={value || t('Unknown')}
        />
      </Tooltip>
    );
  }
  const preClass = small ? classes.smallPre : classes.pre;
  const iconClass = small ? classes.smallIcon : classes.icon;
  return (
    <span className={classes.container}>
      <pre className={preClass}>{value || t('Unknown')}</pre>
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
        <React.Suspense fallback={<ItemOpenVocabDummy small={props.small} chipDisplay={props.chipDisplay} />}>
          <ItemOpenVocabComponent {...props} queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default ItemOpenVocab;
