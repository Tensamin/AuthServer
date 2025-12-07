import { mysqlTable, int, varchar, text, customType } from 'drizzle-orm/mysql-core';
import { createInsertSchema, createSelectSchema } from 'drizzle-zod';
import { z } from 'zod';

export const users = mysqlTable('users', {
  id: int('id').primaryKey().autoincrement(),
  public_key: varchar('public_key', { length: 255 }).notNull(),
  private_key_hash: varchar('private_key_hash', { length: 255 }).notNull(),
  iota_id: int('iota_id').notNull(),
  token: varchar('token', { length: 255 }).notNull(),
  username: varchar('username', { length: 255 }).notNull(),
  display: varchar('display', { length: 255 }),
  avatar: customType<{ data: Uint8Array; driverData: Buffer }>({
    dataType() {
      return 'longblob';
    },
    fromDriver(value: Buffer) {
      return new Uint8Array(value);
    },
    toDriver(value: Uint8Array) {
      return Buffer.from(value);
    },
  })('avatar'),
  about: text('about'),
  status: varchar('status', { length: 255 }),
  sub_level: int('sub_level').notNull().default(0),
  sub_end: int('sub_end').notNull().default(0),
});

export const insertUserSchema = createInsertSchema(users);
export const selectUserSchema = createSelectSchema(users);

export type User = z.infer<typeof selectUserSchema>;
export type NewUser = z.infer<typeof insertUserSchema>;
