import { Body, Controller, Post, Req } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import {
  AuthResponse,
  CurrentUserResponse,
  LoginRequest,
  RegisterRequest,
} from '../../dtos/auth.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Post('login')
  async login(@Body() loginReq: LoginRequest): Promise<AuthResponse> {
    return this.authService.login(loginReq);
  }

  @Post('me')
  async getCurrentUser(@Req() request: Request): Promise<CurrentUserResponse> {
    const token: string = request.headers['Authorization'] as string;
    return this.authService.getCurrentUser(token);
  }

  @Post('register')
  async register(@Body() registerReq: RegisterRequest): Promise<AuthResponse> {
    return this.authService.register(registerReq);
  }
}
