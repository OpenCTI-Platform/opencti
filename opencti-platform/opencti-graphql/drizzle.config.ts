import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
    out: './drizzle',
    schema: './src/schema.ts',
    dialect: 'mysql',
    dbCredentials: {
        url: 'mysql://root@127.0.0.1:4000/opencti'
    },
});