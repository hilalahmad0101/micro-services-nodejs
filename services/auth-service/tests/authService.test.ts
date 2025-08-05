import { AuthService } from './../src/auth.service';



// mock external dependencies
jest.mock('bcryptjs', () => {
    return {
        hash: jest.fn().mockResolvedValue('hashedPassword'),
        compare: jest.fn().mockResolvedValue(true),
    };
});

jest.mock('jsonwebtoken', () => {
    return {
        sign: jest.fn().mockReturnValue('token'),
        verify: jest.fn().mockReturnValue({ userId: 1 }),
    };
});

jest.mock("uuid", () => {
    return {
        v4: jest.fn(),
    };
})


import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { resetAllMocks } from './setup';

describe('AuthService', () => {
    let authService: AuthService;

    beforeAll(() => {
        resetAllMocks();
        authService = new AuthService();
    });

    describe('constructor', () => {
        it('should initialize with environment variables', () => {
            expect(authService).toBeInstanceOf(AuthService);
        });

        it('should have the correct environment variables set', () => {
            expect(process.env.NODE_ENV).toBe('test');
            expect(process.env.PORT).toBe('3001');
            expect(process.env.JWT_SECRET).toBe('your_jwt_secret');
            expect(process.env.JWT_REFRESH_SECRET).toBe('your_jwt_refresh_secret');
            expect(process.env.JWT_EXPIRES_IN).toBe('1h');
            expect(process.env.JWT_REFRESH_EXPIRES_IN).toBe('7d');
            expect(process.env.BCRYPT_ROUNDS).toBe('10');
        });

        it('should have the correct jwt_secret', () => {
            delete process.env.JWT_SECRET;
            expect(() => new AuthService()).toThrow('JWT secrets are not defined in environment variables');
            process.env.JWT_SECRET = 'your_jwt_secret_for_testing_only';
        });

        it('should have the correct jwt_secret_refresh', () => {
            delete process.env.JWT_REFRESH_SECRET;
            expect(() => new AuthService()).toThrow('JWT secrets are not defined in environment variables');
            process.env.JWT_REFRESH_SECRET = 'your_jwt_refresh_secret_for_testing_only';
        });
    });


});

