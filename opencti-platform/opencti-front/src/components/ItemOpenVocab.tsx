import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';
import useVocabularyCategory from '../utils/hooks/useVocabularyCategory';
import { ItemOpenVocabQuery } from './__generated__/ItemOpenVocabQuery.graphql';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import ItemSeverity from './ItemSeverity';
import ItemPriority from './ItemPriority';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: 0,
    display: 'flex',
  },
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: 4,
    width: 120,
    color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
    borderColor: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
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
    textWrap: 'nowrap',
  },
}));

interface ItemOpenVocabProps {
  type: string;
  value?: string | null;
  small?: boolean;
  hideEmpty?: boolean;
  displayMode?: 'chip' | 'span';
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

const ItemOpenVocabDummy = ({
  small = true,
  displayMode = 'span',
}: {
  small?: boolean;
  displayMode?: 'chip' | 'span';
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  if (displayMode === 'chip') {
    return (
      <Tooltip title={t_i18n('No description')}>
        <Chip classes={{ root: classes.chip }} label={t_i18n('Unknown')} />
      </Tooltip>
    );
  }
  return (
    <span className={classes.container}>
      <pre className={small ? classes.smallPre : classes.pre}>
        {t_i18n('Unknown')}
      </pre>
      <Tooltip title={t_i18n('No description')}>
        <InformationOutline
          className={small ? classes.smallIcon : classes.icon}
          fontSize="small"
          color="disabled"
        />
      </Tooltip>
    </span>
  );
};
const ItemOpenVocabComponent: FunctionComponent<ItemOpenVocabProps> = ({
  type,
  value,
  small = true,
  hideEmpty = true,
  displayMode = 'span',
  queryRef,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { vocabularies } = usePreloadedQuery<ItemOpenVocabQuery>(
    itemOpenVocabQuery,
    queryRef,
  );
  let description = null;
  if (value) {
    const openVocabList = (vocabularies?.edges ?? []).map(({ node }) => node);
    const openVocab = openVocabList.find((n) => n.name === value);
    description = openVocab?.description ? openVocab.description : null;
  }
  if (displayMode === 'chip') {
    let chip = (
      <Chip classes={{ root: classes.chip }} label={value || t_i18n('Unknown')} />
    );
    if (type === 'case_severity_ov') {
      chip = <ItemSeverity label={value || t_i18n('Unknown')} severity={value} />;
    } else if (type === 'case_priority_ov') {
      chip = <ItemPriority label={value || t_i18n('Unknown')} priority={value} />;
    }
    return !description && hideEmpty ? (
      chip
    ) : (
      <Tooltip title={t_i18n(description ?? t_i18n('No description'))}>
        <span>{chip}</span>
      </Tooltip>
    );
  }
  const preClass = small ? classes.smallPre : classes.pre;
  const iconClass = small ? classes.smallIcon : classes.icon;
  const tooltip = (
    <Tooltip title={t_i18n(description ?? t_i18n('No description'))}>
      <InformationOutline
        className={iconClass}
        fontSize="small"
        color="secondary"
      />
    </Tooltip>
  );
  return (
    <span className={classes.container}>
      <pre className={preClass}>{value || t_i18n('Unknown')}</pre>
      {!description && hideEmpty ? '' : tooltip}
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
        <React.Suspense
          fallback={
            <ItemOpenVocabDummy
              small={props.small}
              displayMode={props.displayMode}
            />
          }
        >
          <ItemOpenVocabComponent {...props} queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default ItemOpenVocab;
