import { AuthService } from './../src/auth.service';
// mock external dependencies
jest.mock('bcrypt', () => {
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
        it('should initialize waith environment variables', () => {
            expect(authService).toBeInstanceOf(AuthService);
        });
    });
});

