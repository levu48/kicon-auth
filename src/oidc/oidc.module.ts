import { Module } from '@nestjs/common';
import { PersistenceModule } from '../database/persistence.module';
import { OidcService } from './oidc.service';

@Module({
  imports: [PersistenceModule], // AccountsService + IdentityService for findAccount
  providers: [OidcService],
  exports: [OidcService],
})
export class OidcModule {}
