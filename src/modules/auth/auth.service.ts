import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { DbService } from '../db/db.service';
import {
  AuthResponse,
  CurrentUserResponse,
  LoginRequest,
  RegisterRequest,
} from '../../dtos/auth.dto';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import User from '../../entities/User';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly dbService: DbService,
  ) {}

  async login({ username, password }: LoginRequest): Promise<AuthResponse> {
    if (!this.dbService.conn) await this.dbService.connect();
    let userRepository = this.dbService.conn.getRepository(User);

    // Check for existing account
    let user: User = await userRepository.findOne({
      where: { username },
    });

    // Account Not Found
    if (!user)
      throw new HttpException('Invalid Credentials', HttpStatus.BAD_REQUEST);

    // Compare Passwords
    if (await bcrypt.compare(password, user.password)) {
      // Generate jwt
      let jwtSecret = this.configService.get<string>('JWT_SECRET')!;
      let token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '7d' });
      delete user.password;
      return { token, user };
    }

    throw new HttpException('Invalid Credentials', HttpStatus.BAD_REQUEST);
  }

  async getCurrentUser(token: string): Promise<CurrentUserResponse> {
    if (!this.dbService.conn) await this.dbService.connect();
    let userRepository = this.dbService.conn.getRepository(User);

    // Make sure token exists
    token = token.replace('Bearer ', '');
    if (!token)
      throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);

    // Validate token
    let jwtSecret = this.configService.get<string>('JWT_SECERT');
    if (jwt.verify(token, jwtSecret)) {
      // Get Associated User
      let jwtPayload: jwt.JwtPayload = (await jwt.decode(
        token,
      )) as jwt.JwtPayload;

      let user = await userRepository.findOne(parseInt(jwtPayload['id']));
      delete user.password;

      return { user };
    }

    throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);
  }

  async register({
    username,
    email,
    password,
  }: RegisterRequest): Promise<AuthResponse> {
    if (!this.dbService.conn) await this.dbService.connect();
    let userRepository = this.dbService.conn.getRepository(User);

    // Validate all fields are valid
    if (
      !username ||
      !password ||
      !email.includes('@') ||
      !email.includes('.')
    ) {
      throw new HttpException('Invalid Credentials', HttpStatus.BAD_REQUEST);
    }

    // Check for existing account
    let existingUser = await userRepository.findOne({
      where: { username, email },
    });

    // Account Found
    if (existingUser) {
      throw new HttpException(
        'Account Exists With Provided Username or Email',
        HttpStatus.BAD_REQUEST,
      );
    }

    // Hash Password
    let hashed_pw = await bcrypt.hash(password, await bcrypt.genSalt());

    // Create new User Entity
    let user = new User();
    user.email = email;
    user.password = hashed_pw;
    user.username = username;

    // Insert into DB
    let insertedUser = await userRepository.save(user);

    if (insertedUser) {
      // Generate jwt
      let jwtSecret = this.configService.get<string>('JWT_SECRET')!;
      let token = jwt.sign({ id: insertedUser.id }, jwtSecret, {
        expiresIn: '7d',
      });
      return { token, user: insertedUser };
    }

    throw new HttpException(
      'Something Went Wrong',
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }
}
