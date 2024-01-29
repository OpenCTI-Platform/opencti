import { test, expect } from '@playwright/test';
import { login } from "../common/login";
import { logout } from "../common/logout";

  test('Log to Filigran App and  Log out', async ({ page }) => {
    await login(page);
    await logout(page);
  });
