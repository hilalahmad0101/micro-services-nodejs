import { logError, ServiceError } from '../types';
import { createErrorResponse } from '../utils';
import { Request, Response, NextFunction } from 'express';


// extends express request interface to include a custom properties

declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}


export function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}


export function validateSchema(schema: any) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { error } = schema.validate(req.body);
        if (error) {
            const errors: Record<string, string[]> = {}
            error.details.forEach((detail: any) => {
                const field = detail.path.join('.');
                if (!errors[field]) {
                    errors[field] = [];
                }
                errors[field].push(detail.message);
            });
            return res.status(400).json({
                success: false,
                error: 'Validation error',
                errors,
            });
        }
        return next();
    }
}


export function errorHandler(
    error: ServiceError,
    req: Request,
    res: Response,
    next: NextFunction
) {
    logError(error, {
        method: req.method,
        url: req.originalUrl,
        body: req.body,
        query: req.query,
        params: req.params
    });

    const statusCode = error.statusCode || 500;
    const message = error.message || "Internal Server Error";


    res.status(statusCode).json(createErrorResponse(message, statusCode, error.details));

    next();
}