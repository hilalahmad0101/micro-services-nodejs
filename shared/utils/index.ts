import { ApiResponse, logError, ServiceError } from "../types";
import { Request, Response, NextFunction } from "express";
export function createApiResponse<T>(
    success: boolean,
    data?: T,
    message?: string,
    error?: string,
    errors?: Record<string, string[]>
): ApiResponse<T> {
    return {
        success,
        data,
        message,
        error,
        errors
    };
}


export function createServiceError(
    message: string,
    statusCode: number = 500,
    code?: string,
    details?: any
): ServiceError {
    return new ServiceError(message, statusCode, code, details);
}


export function createSuccessResponse<T>(
    data: T,
    message?: string
): ApiResponse<T> {
    return createApiResponse(true, data, message);
}

export function createErrorResponse(
    error: string,
    statusCode: number = 500,
    errors?: Record<string, string[]>
): ApiResponse {
    return createApiResponse(false, undefined, undefined, error, errors);
}

