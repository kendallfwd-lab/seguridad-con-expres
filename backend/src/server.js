import { createApp } from './app.js';
import { createPool, checkDatabase } from './config/database.js';
import { loadEnv } from './config/env.js';

const env = loadEnv();
const pool = createPool(env);
await checkDatabase(pool);
const app = await createApp({ pool, env });
const server = app.listen(env.PORT, '127.0.0.1', () => console.log(`Security Lab API listening on ${env.PORT}`));
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close(() => pool.end()));
