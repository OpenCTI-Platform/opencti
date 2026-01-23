import { createContext, PropsWithChildren, useContext, useState } from 'react';
import { ResetPwdStep } from './ResetPassword';

interface LoginContextData {
  email: string;
  resetPwdStep?: ResetPwdStep;
  resendCodeDisabled?: boolean;
  validateOtpInError?: boolean;
  changePasswordInError?: boolean;
  mfaInError?: boolean;
  pwdChanged?: boolean;
};

type ContextValue = LoginContextData & {
  setValue: <K extends keyof LoginContextData>(
    key: K,
    value: LoginContextData[K],
  ) => void;
} | undefined;

const LoginContext = createContext<ContextValue>(undefined);

export const LoginContextProvider = ({ children }: PropsWithChildren) => {
  const [data, setData] = useState<LoginContextData>({ email: '' });

  const setValue = <K extends keyof LoginContextData>(
    key: K,
    value: LoginContextData[K],
  ) => {
    setData((oldState) => {
      return { ...oldState, [key]: value };
    });
  };

  return (
    <LoginContext.Provider value={{ ...data, setValue }}>
      {children}
    </LoginContext.Provider>
  );
};

export const useLoginContext = () => {
  const context = useContext(LoginContext);
  if (!context) throw Error('Hook used outside of LoginContextProvider');
  return context;
};
