import { Module } from '@nestjs/common';
import { LoginThrottleService } from './login-throttle.service';
import { BreachedPasswordService } from './breached-password.service';

/** Login-hardening services (Redis-backed throttle + HIBP breach check). */
@Module({
  providers: [LoginThrottleService, BreachedPasswordService],
  exports: [LoginThrottleService, BreachedPasswordService],
})
export class SecurityModule {}
