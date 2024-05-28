import React from 'react';
import { EffectiveConfidenceLevelSourceType } from '@components/settings/users/__generated__/User_user.graphql';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';

type UserConfidenceOverridesProps = {
  overrides: readonly {
    readonly entity_type: string,
    readonly max_confidence: number,
    readonly source: {
      readonly object: {
        readonly entity_type?: string | undefined,
        readonly id?: string | undefined,
        readonly name?: string | undefined
      } | null | undefined,
      readonly type: EffectiveConfidenceLevelSourceType
    } | null | undefined
  }[]
};

type OverrideConfidenceSourceProps = {
  override: UserConfidenceOverridesProps['overrides'][0]
};

const OverrideConfidenceWithSource: React.FC<OverrideConfidenceSourceProps> = ({ override, ...rest }) => {
  const { t_i18n } = useFormatter();
  const { max_confidence, source, entity_type } = override;

  let from;
  if (source?.object?.entity_type === 'Group') {
    from = t_i18n('', {
      id: 'from group ...',
      values: {
        link: (
          <Link to={`/dashboard/settings/accesses/groups/${source.object.id}`}>
            {source.object.name}
          </Link>
        ),
      },
    });
  } else {
    from = t_i18n('from user');
  }

  return (
    <div {...rest}>
      {`- ${t_i18n(`entity_${entity_type}`)}: ${max_confidence}`}&nbsp;
      {source
        ? <span>({from})</span>
        : null
      }
    </div>
  );
};

const UserConfidenceOverrides: React.FC<UserConfidenceOverridesProps> = ({ overrides }) => {
  const { t_i18n } = useFormatter();
  return overrides?.length ? (
    <div style={{ marginTop: '5px' }}>
      <div>{t_i18n('Max Confidence is overridden for some entity types:')}</div>
      {overrides.map((override, index) => (
        <OverrideConfidenceWithSource
          key={`override-${override.entity_type}-${index}`}
          override={override}
        />
      ))}
    </div>
  ) : null;
};

export default UserConfidenceOverrides;
