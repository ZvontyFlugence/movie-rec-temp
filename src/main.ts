import { NestFactory } from '@nestjs/core';
import { AppModule } from './modules/app/app.module';

import 'reflect-metadata';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: true });

  await app.listen(parseInt(process.env.PORT, 10) || 5000);
}
bootstrap();
