import { createApp } from '../backend/src/app.js';
import { createPool } from '../backend/src/config/database.js';
import { loadEnv } from '../backend/src/config/env.js';

let appPromise = null;

function getApp() {
  if (!appPromise) {
    appPromise = (async () => {
      const env = loadEnv();
      const pool = createPool(env);
      return createApp({ pool, env });
    })().catch((error) => {
      appPromise = null;
      throw error;
    });
  }
  return appPromise;
}

export default async function handler(req, res) {
  const app = await getApp();
  return app(req, res);
}
