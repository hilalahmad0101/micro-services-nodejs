// shared typescript types definition for all microservice

export interface User {
    id: string;
    email: string;
    createdAt: Date;
    updateAt: Date;
}


export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    message?: string;
    error?: string;
    errors?: Record<string, string[]>;
}

export interface AuthTokens {
    accessToken: AuthAccessToken;
    refreshToken: AuthRefreshToken;
}

export interface AuthAccessToken {
    accessToken: string;
}

export interface AuthRefreshToken {
    refreshToken: string;
}

export interface JWTPayload {
    userId: string;
    email: string;
    iat: number; // issued at
    exp: number; // expiration time
}


export class ServiceError extends Error {
    statusCode: number;
    code?: string;
    details?: any;

    /**
     * Custom error class for service errors
     * @param message - Error message
     * @param statusCode - HTTP status code (default: 500)
     * @param code - Optional custom error code
     * @param details - Optional additional details about the error
     */
    constructor(message: string, statusCode: number = 500, code?: string, details?: any) {
        super(message);
        this.statusCode = statusCode;
        this.name = "ServiceError";
        if (code) {
            this.code = code;
        }
        if (details) {
            this.details = details;
        }
    }
}

export function logError(error: Error, context?: Record<string, any>) {
    console.error("Error:", {
        message: error.message,
        stack: error.stack,
        context: context || {},
        timestamp: new Date().toISOString(),
    });

}