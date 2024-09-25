import useAuth from './useAuth';
import useScale from './useScale';

const PROTECT_SENSITIVE_CHANGES_FF = 'PROTECT_SENSITIVE_CHANGES';

const useSensitiveModifications = () => {
    const { me } = useAuth();
    // with FF  & me.sensitve truc;
    return {ffenabled: true, isSensitiveModifAllowed: true};
};

export default useSensitiveModifications;