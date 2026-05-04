import { useFormatter } from '../../../../../components/i18n';

const CustomViewEditionMissingContextEntityFiller = () => {
  const { t_i18n } = useFormatter();
  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        textAlign: 'center',
      }}
    >
      {t_i18n('Use the entity selector above to get a preview of the widget content.')}
    </div>
  );
};

export default CustomViewEditionMissingContextEntityFiller;
