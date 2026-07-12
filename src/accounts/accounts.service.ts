import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import { User } from '../database/entities';

/**
 * Ring-1 core + credentials, now Postgres-backed (was the in-memory
 * accounts.store). Passwords are Argon2id (CLAUDE.md); we store only the hash.
 */
@Injectable()
export class AccountsService {
  constructor(@InjectRepository(User) private readonly users: Repository<User>) {}

  findById(id: string): Promise<User | null> {
    return this.users.findOne({ where: { id } });
  }

  findByEmail(email: string): Promise<User | null> {
    return this.users.findOne({ where: { primary_email: (email ?? '').trim().toLowerCase() } });
  }

  /** Constant-time Argon2id verify. */
  async verifyPassword(user: User, plain: string): Promise<boolean> {
    if (!user?.password_hash || !plain) return false;
    try {
      return await argon2.verify(user.password_hash, plain);
    } catch {
      return false;
    }
  }

  hash(plain: string): Promise<string> {
    return argon2.hash(plain, { type: argon2.argon2id });
  }

  /** Opaque, stable `sub` for a new account. */
  static newId(): string {
    return 'u_' + randomBytes(8).toString('hex');
  }

  /**
   * Create a Ring-1 account with Argon2id credentials. Email is normalised to
   * match findByEmail. Relies on the `users.primary_email` unique constraint as
   * the final guard against races (callers should still pre-check for a friendly
   * message). Used by the /register flow; the admin CLI has its own DataSource path.
   */
  async create(input: {
    email: string;
    name: string;
    password: string;
    locale?: string | null;
    zoneinfo?: string | null;
  }): Promise<User> {
    const user = this.users.create({
      id: AccountsService.newId(),
      primary_email: (input.email ?? '').trim().toLowerCase(),
      name: input.name.trim(),
      default_locale: input.locale ?? null,
      default_zoneinfo: input.zoneinfo ?? null,
      password_hash: await this.hash(input.password),
    });
    return this.users.save(user);
  }
}
