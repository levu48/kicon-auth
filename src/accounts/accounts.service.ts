import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
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
}
