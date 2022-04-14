import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let authController: AuthController;

  beforeEach(async () => {
    const authModule: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [AuthService],
    }).compile();

    authController = authModule.get<AuthController>(AuthController);
  });

  describe('login', () => {
    it('should return jwt', () => {
      expect(
        authController.login({ username: 'admin', password: 'password' }),
      ).toContain<{ token: string }>({
        token: 'token value',
      });
    });
  });
});
