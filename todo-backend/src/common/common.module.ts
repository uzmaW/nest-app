import { Module, Global } from '@nestjs/common';
import { RequestContext } from './request-context';

@Global()
@Module({
  providers: [RequestContext],
  exports: [RequestContext],
})
export class CommonModule {}