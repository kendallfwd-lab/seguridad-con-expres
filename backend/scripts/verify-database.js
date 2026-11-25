import { createPool, checkDatabase } from '../src/config/database.js';
import { loadEnv } from '../src/config/env.js';

const pool = createPool(loadEnv());
try {
  const health = await checkDatabase(pool);
  const schemas = await pool.query("select schema_name from information_schema.schemata where schema_name='app_private'");
  const tables = await pool.query("select table_name from information_schema.tables where table_schema='app_private' order by table_name");
  const privileges = schemas.rowCount && tables.rows.some((row) => row.table_name === 'users')
    ? (await pool.query("select has_database_privilege(current_user,current_database(),'CREATE') as can_create_database, has_schema_privilege(current_user,'app_private','CREATE') as can_create_schema, has_table_privilege(current_user,'app_private.users','SELECT') as can_select_users")).rows[0]
    : null;
  console.log(JSON.stringify({ health, schemaExists: schemas.rowCount === 1, tableCount: tables.rowCount, tables: tables.rows.map((row) => row.table_name), privileges }, null, 2));
} finally {
  await pool.end();
}
