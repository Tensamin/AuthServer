import { drizzle } from 'drizzle-orm/mysql2';
import mysql from 'mysql2/promise';
import * as schema from './schema.ts';

const poolConnection = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWD,
  database: process.env.DB_NAME || 'tensamin',
  port: Number(process.env.DB_PORT) || 3306,
});

export const db = drizzle(poolConnection, { schema, mode: 'default' });
