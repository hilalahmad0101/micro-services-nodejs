process.env.NODE_ENV = "test"
process.env.PORT = "3001"
process.env.JWT_SECRET = "your_jwt_secret"
process.env.JWT_REFRESH_SECRET = "your_jwt_refresh_secret"
process.env.JWT_EXPIRES_IN = "1h"
process.env.JWT_REFRESH_EXPIRES_IN = "7d"
process.env.BCRYPT_ROUNDS = "10"


const mockPrismaClient = {
    user: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
        findMany: jest.fn(),
        findFirst: jest.fn(),
        count: jest.fn(),
    },
    refreshToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        delete: jest.fn(),
        findMany: jest.fn(),
        count: jest.fn(),
        deleteMany: jest.fn(),
    },
    $disconnect: jest.fn(),
    $connect: jest.fn(),
}

// mock the database module
jest.mock('../src/database', () => mockPrismaClient);


//  mock test utils

global.mockPrisma = mockPrismaClient;

export function resetAllMocks() {
    Object.keys(mockPrismaClient.user).forEach((mock) => {
        if (jest.isMockFunction(mock)) {
            mock.mockReset();
        }
    });

    Object.keys(mockPrismaClient.refreshToken).forEach((mock) => {
        if (jest.isMockFunction(mock)) {
            mock.mockReset();
        }
    });
}

declare global {
    var mockPrisma: typeof mockPrismaClient;
}