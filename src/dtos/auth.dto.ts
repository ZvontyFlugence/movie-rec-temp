import User from '../entities/User';

export class LoginRequest {
  username: string;
  password: string;
}

export class AuthResponse {
  token?: string;
  user?: User;
}

export class CurrentUserResponse {
  user?: User;
}

export class RegisterRequest {
  username: string;
  email: string;
  password: string;
}
