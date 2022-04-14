import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import User from 'entities/User';
import * as mysql from 'mysql2';
import { createConnection, Connection } from 'typeorm';

interface DbConfig {
  host: string;
  user: string;
  password: string;
  database: string;
}

@Injectable()
export class DbService {
  conn: Connection;

  constructor(private readonly configService: ConfigService) {}

  async connect(): Promise<void> {
    const dbConfig = this.configService.get<DbConfig>('db')!;

    this.conn = await createConnection({
      type: 'mysql',
      driver: mysql,
      host: dbConfig.host,
      port: 3306,
      username: dbConfig.user,
      password: dbConfig.password,
      database: dbConfig.database,
      ssl: {
        rejectUnauthorized: true,
      },
      synchronize: true,
      logging: false,
      entities: [User],
      migrations: ['../../migrations/*.{ts,js}'],
    });
  }
}
