const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// Rate limiting for auth routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs for auth
    message: 'Too many authentication attempts, please try again later.'
});

// In-memory storage (replace with database in production)
const users = [];
const sessions = [];

// Validation middleware
const validateRegister = [
    body('fullName').trim().isLength({ min: 2 }).withMessage('ชื่อต้องมีอย่างน้อย 2 ตัวอักษร'),
    body('phone').matches(/^0[0-9]{8,9}$/).withMessage('เบอร์โทรศัพท์ไม่ถูกต้อง'),
    body('email').isEmail().normalizeEmail().withMessage('อีเมลไม่ถูกต้อง'),
    body('password').isLength({ min: 8 }).withMessage('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร'),
    body('userType').isIn(['เจ้าของห้อง', 'นายหน้า', 'ผู้ซื้อ/เช่า']).withMessage('ประเภทผู้ใช้ไม่ถูกต้อง')
];

const validateLogin = [
    body('email').isEmail().normalizeEmail().withMessage('อีเมลไม่ถูกต้อง'),
    body('password').notEmpty().withMessage('กรุณากรอกรหัสผ่าน')
];

// Helper functions
const generateToken = (userId) => {
    return jwt.sign(
        { userId, timestamp: Date.now() },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );
};

const findUserByEmail = (email) => {
    return users.find(user => user.email === email);
};

// Routes

// POST /api/auth/register
router.post('/register', authLimiter, validateRegister, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'ข้อมูลไม่ถูกต้อง',
                errors: errors.array()
            });
        }

        const { fullName, phone, email, password, userType } = req.body;

        // Check if user already exists
        if (findUserByEmail(email)) {
            return res.status(409).json({
                success: false,
                message: 'อีเมลนี้มีผู้ใช้แล้ว'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS));

        // Create user
        const newUser = {
            id: users.length + 1,
            fullName,
            phone,
            email,
            password: hashedPassword,
            userType,
            verified: false,
            createdAt: new Date(),
            profileComplete: false
        };

        users.push(newUser);

        // Generate verification code (simulate email verification)
        const verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        
        // In production, send email here
        console.log(`Verification code for ${email}: ${verificationCode}`);

        // Create session without sensitive data
        const userResponse = {
            id: newUser.id,
            fullName: newUser.fullName,
            email: newUser.email,
            userType: newUser.userType,
            verified: newUser.verified,
            profileComplete: newUser.profileComplete
        };

        res.status(201).json({
            success: true,
            message: 'ลงทะเบียนสำเร็จ กรุณายืนยันตัวตนผ่านอีเมล',
            user: userResponse,
            verificationCode // Remove this in production
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการลงทะเบียน'
        });
    }
});

// POST /api/auth/login
router.post('/login', authLimiter, validateLogin, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'ข้อมูลไม่ถูกต้อง',
                errors: errors.array()
            });
        }

        const { email, password } = req.body;

        // Find user
        const user = findUserByEmail(email);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง'
            });
        }

        // Generate token
        const token = generateToken(user.id);

        // Update last login
        user.lastLogin = new Date();

        // Store session
        sessions.push({
            userId: user.id,
            token,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        });

        const userResponse = {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            userType: user.userType,
            verified: user.verified,
            profileComplete: user.profileComplete
        };

        res.json({
            success: true,
            message: 'เข้าสู่ระบบสำเร็จ',
            token,
            user: userResponse
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
        });
    }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (token) {
        // Remove session
        const sessionIndex = sessions.findIndex(s => s.token === token);
        if (sessionIndex > -1) {
            sessions.splice(sessionIndex, 1);
        }
    }

    res.json({
        success: true,
        message: 'ออกจากระบบสำเร็จ'
    });
});

// GET /api/auth/me - Get current user info
router.get('/me', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'ไม่มี token'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const session = sessions.find(s => s.token === token);
        
        if (!session || session.expiresAt < new Date()) {
            return res.status(401).json({
                success: false,
                message: 'Token หมดอายุ'
            });
        }

        // Find user
        const user = users.find(u => u.id === decoded.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'ไม่พบผู้ใช้'
            });
        }

        const userResponse = {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            phone: user.phone,
            userType: user.userType,
            verified: user.verified,
            profileComplete: user.profileComplete,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };

        res.json({
            success: true,
            user: userResponse
        });

    } catch (error) {
        console.error('Auth verification error:', error);
        res.status(401).json({
            success: false,
            message: 'Token ไม่ถูกต้อง'
        });
    }
});

// GET /api/auth/stats - Get registration stats (admin only)
router.get('/stats', (req, res) => {
    const stats = {
        totalUsers: users.length,
        verifiedUsers: users.filter(u => u.verified).length,
        usersByType: {
            'เจ้าของห้อง': users.filter(u => u.userType === 'เจ้าของห้อง').length,
            'นายหน้า': users.filter(u => u.userType === 'นายหน้า').length,
            'ผู้ซื้อ/เช่า': users.filter(u => u.userType === 'ผู้ซื้อ/เช่า').length
        },
        activeSessions: sessions.filter(s => s.expiresAt > new Date()).length
    };

    res.json({
        success: true,
        stats
    });
});

module.exports = router;
