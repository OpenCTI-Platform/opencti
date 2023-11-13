import type { CurrencyCode, FinancialAccountBalance, FinancialAccountStatus, FinancialAccountType } from '../../generated/graphql';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_FINANCIAL_ACCOUNT = 'Financial-Account';

export interface BasicStoreEntityFinancialAccount extends BasicStoreEntity {
  currency_code: CurrencyCode;
  name: string;
  financial_account_number: string;
  financial_account_status: FinancialAccountStatus;
  financial_account_type: FinancialAccountType;
  financial_account_balances: FinancialAccountBalance[];
  international_bank_account_number: string;
}

export interface StoreEntityFinancialAccount extends StoreEntity {
  currency_code: string;
  name: string;
  financial_account_number: string;
  financial_account_status: string;
  financial_account_type: string;
  financial_account_balances: string[];
  international_bank_account_number: string;
}
