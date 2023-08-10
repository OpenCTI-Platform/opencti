import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { HiddenTypesIndicatorQuery } from './__generated__/HiddenTypesIndicatorQuery.graphql';

const hiddenTypesIndicatorQuery = graphql`
  query HiddenTypesIndicatorQuery {
    groups {
      edges {
        node {
          id
          name
          default_hidden_types
        }
      }
    }
    organizations {
      edges {
        node {
          id
          name
          default_hidden_types
        }
      }
    }
  }
`;

const useStyles = makeStyles<Theme>((theme) => ({
  indication: {
    fontSize: 12,
    color: theme.palette.primary.main,
  },
}));

interface HiddenTypesIndicatorComponentProps {
  platformHiddenTargetType: string
  queryRef: PreloadedQuery<HiddenTypesIndicatorQuery>
}

const HiddenTypesIndicatorComponent: FunctionComponent<HiddenTypesIndicatorComponentProps> = ({
  platformHiddenTargetType,
  queryRef,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const data = usePreloadedQuery<HiddenTypesIndicatorQuery>(hiddenTypesIndicatorQuery, queryRef);
  const groups = data.groups?.edges?.map((e) => e?.node) ?? [];
  const organizations = data.organizations?.edges?.map((e) => e?.node) ?? [];

  const groupsName: string[] = [];

  groups.forEach((group) => {
    if (group?.default_hidden_types) {
      if (group.default_hidden_types.includes(platformHiddenTargetType)) {
        groupsName.push(group.name);
      }
    }
  });

  const orgsName: string[] = [];

  organizations.forEach((org) => {
    if (org?.default_hidden_types) {
      if (org.default_hidden_types.includes(platformHiddenTargetType)) {
        orgsName.push(org.name);
      }
    }
  });

  return (
    <span>
      {(groupsName.length > 0 || orgsName.length > 0)
        && (<span className={classes.indication}>
              &emsp;
          {`(${t('Hidden in ')}`}
          {groupsName.length > 0 && `${t('groups ')} : ${groupsName}`}
          {(groupsName.length > 0 && orgsName.length > 0) && `${t(' and ')}`}
          {orgsName.length > 0 && `${t('organizations ')} : ${orgsName}`}
          {')'}
            </span>)
      }
    </span>
  );
};

interface HiddenTypesIndicatorProps {
  platformHiddenTargetType: string,
}

const HiddenTypesIndicator: FunctionComponent<HiddenTypesIndicatorProps> = ({
  platformHiddenTargetType,
}) => {
  const queryRef = useQueryLoading<HiddenTypesIndicatorQuery>(hiddenTypesIndicatorQuery, {});

  return (
      <>
        {queryRef && (
            <React.Suspense
                fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <HiddenTypesIndicatorComponent
                  queryRef={queryRef}
                  platformHiddenTargetType={platformHiddenTargetType}
              />
            </React.Suspense>)
        }
      </>
  );
};

export default HiddenTypesIndicator;
