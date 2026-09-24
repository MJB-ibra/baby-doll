require('dotenv').config()

const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const axios = require('axios')
const mysql = require('mysql2/promise')

const app = express()
const PORT = Number(process.env.PORT || 3230)

for (const key of ['JWT_SECRET']) {
    if (!process.env[key]) throw new Error(`${key} is required in .env`)
}

const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'baby_doll',
    waitForConnections: true,
    connectionLimit: 10,
    decimalNumbers: true
})

app.use(helmet())
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true
}))
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30
})

const PAYMENT = {
    PENDING: 'PENDING',
    SUCCESS: 'SUCCESS',
    FAILED: 'FAILED',
    CANCELLED: 'CANCELLED'
}

const DELIVERY = {
    PENDING: 'PENDING',
    ASSIGNED: 'ASSIGNED',
    PICKED_UP: 'PICKED_UP',
    OUT_FOR_DELIVERY: 'OUT_FOR_DELIVERY',
    CUSTOMER_ACCEPTED: 'CUSTOMER_ACCEPTED',
    COURIER_ACCEPTED: 'COURIER_ACCEPTED',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED'
}

function normalizeRwPhone(phone) {
    const value = String(phone || '').replace(/\s+/g, '')
    if (/^07\d{8}$/.test(value)) return '25' + value
    if (/^2507\d{8}$/.test(value)) return value
    if (/^\+2507\d{8}$/.test(value)) return value.slice(1)
    throw new Error('Invalid Rwanda phone number')
}

function reference() {
    return crypto.randomUUID()
}

function deliveryCodeHash(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex')
}

function signToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
    )
}

function authCookie(res, user) {
    res.cookie('access_token', signToken(user), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 86400000
    })
}

function requireAuth(req, res, next) {
    (async () => {
        try {
            const token = req.cookies.access_token
            if (!token) return res.status(401).json({ message: 'Authentication required' })

            const payload = jwt.verify(token, process.env.JWT_SECRET)
            const [rows] = await db.query(
                `SELECT id,username,role,image,status FROM users WHERE id=? LIMIT 1`,
                [payload.id]
            )

            if (!rows.length) return res.status(401).json({ message: 'Account not found' })
            if (rows[0].status && rows[0].status !== 'ACTIVE') {
                return res.status(403).json({ message: 'Account is not active' })
            }

            req.user = rows[0]
            next()
        } catch {
            res.status(401).json({ message: 'Invalid or expired session' })
        }
    })()
}

function role(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied' })
        }
        next()
    }
}

async function hasPermission(user, permission) {
    if (user.role === 'admin') return true

    /* A direct user permission overrides the role default.
       This lets Admin explicitly allow OR deny a task for one worker. */
    const [direct] = await db.query(
        `SELECT up.allowed
         FROM user_permissions up
         JOIN permissions p ON p.id=up.permission_id
         WHERE up.user_id=? AND p.name=? LIMIT 1`,
        [user.id, permission]
    )

    if (direct.length) return Boolean(direct[0].allowed)

    const [roleRows] = await db.query(
        `SELECT 1
         FROM role_permissions rp
         JOIN permissions p ON p.id=rp.permission_id
         WHERE rp.role=? AND p.name=? AND rp.allowed=1
         LIMIT 1`,
        [user.role, permission]
    )

    return roleRows.length > 0
}

function requirePermission(permission) {
    return async (req, res, next) => {
        try {
            if (await hasPermission(req.user, permission)) return next()
            return res.status(403).json({
                message: 'Permission denied',
                required_permission: permission
            })
        } catch (error) {
            console.error('Permission check failed:', error)
            return res.status(500).json({ message: 'Permission check failed' })
        }
    }
}

function requireAnyPermission(...permissions) {
    return async (req, res, next) => {
        try {
            for (const permission of permissions) {
                if (await hasPermission(req.user, permission)) return next()
            }
            return res.status(403).json({ message: 'Permission denied' })
        } catch (error) {
            console.error('Permission check failed:', error)
            return res.status(500).json({ message: 'Permission check failed' })
        }
    }
}

async function audit(userId, action, resource, resourceId, details = null) {
    try {
        await db.query(
            `INSERT INTO audit_logs(user_id,action,resource,resource_id,details)
             VALUES(?,?,?,?,?)`,
            [userId, action, resource, resourceId || null, details ? JSON.stringify(details) : null]
        )
    } catch (error) {
        console.error('Audit log failed:', error.message)
    }
}

/* =========================================================
   SMS
   MTN SMS v3 is available in Rwanda. The endpoint/credentials
   are kept in .env because MTN provisions them per application.
========================================================= */

async function sendSMS(to, message) {
    const phone = normalizeRwPhone(to)

    if (process.env.SMS_PROVIDER === 'console') {
        console.log(`[SMS SAMPLE] ${phone}: ${message}`)
        return { sent: true, provider: 'console' }
    }

    if (process.env.SMS_PROVIDER !== 'mtn') {
        throw new Error('SMS_PROVIDER must be mtn or console')
    }

    const tokenResponse = await axios.post(
        process.env.MTN_SMS_TOKEN_URL,
        new URLSearchParams({
            grant_type: 'client_credentials'
        }),
        {
            auth: {
                username: process.env.MTN_SMS_CLIENT_ID,
                password: process.env.MTN_SMS_CLIENT_SECRET
            },
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 15000
        }
    )

    const token = tokenResponse.data.access_token

    const response = await axios.post(
        process.env.MTN_SMS_SEND_URL,
        {
            senderAddress: process.env.MTN_SMS_SENDER,
            receiverAddress: [phone],
            message
        },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...(process.env.MTN_SMS_SUBSCRIPTION_KEY
                    ? { 'Ocp-Apim-Subscription-Key': process.env.MTN_SMS_SUBSCRIPTION_KEY }
                    : {})
            },
            timeout: 15000
        }
    )

    return { sent: true, provider: 'mtn', data: response.data }
}

async function safeSMS(to, message) {
    try {
        return await sendSMS(to, message)
    } catch (error) {
        console.error('SMS failed:', error.response?.data || error.message)
        return { sent: false }
    }
}

/* =========================================================
   MTN MOMO
========================================================= */

async function mtnMomoToken() {
    const basic = Buffer.from(
        `${process.env.MTN_MOMO_API_USER}:${process.env.MTN_MOMO_API_KEY}`
    ).toString('base64')

    const response = await axios.post(
        `${process.env.MTN_MOMO_BASE_URL}/collection/token/`,
        {},
        {
            headers: {
                Authorization: `Basic ${basic}`,
                'Ocp-Apim-Subscription-Key': process.env.MTN_MOMO_SUBSCRIPTION_KEY
            },
            timeout: 15000
        }
    )

    return response.data.access_token
}

async function startMtnMomoPayment({ amount, phone, referenceId, orderId }) {
    const token = await mtnMomoToken()
    const target = normalizeRwPhone(phone)

    await axios.post(
        `${process.env.MTN_MOMO_BASE_URL}/collection/v1_0/requesttopay`,
        {
            amount: String(amount),
            currency: 'RWF',
            externalId: String(orderId),
            payer: {
                partyIdType: 'MSISDN',
                partyId: target
            },
            payerMessage: `Payment for order ${orderId}`,
            payeeNote: `Baby Doll order ${orderId}`
        },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'X-Reference-Id': referenceId,
                'X-Target-Environment': process.env.MTN_MOMO_TARGET_ENV || 'sandbox',
                'Ocp-Apim-Subscription-Key': process.env.MTN_MOMO_SUBSCRIPTION_KEY,
                'Content-Type': 'application/json'
            },
            timeout: 15000
        }
    )

    return { provider: 'MTN_MOMO', referenceId }
}

async function getMtnMomoStatus(referenceId) {
    const token = await mtnMomoToken()

    const response = await axios.get(
        `${process.env.MTN_MOMO_BASE_URL}/collection/v1_0/requesttopay/${referenceId}`,
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'X-Target-Environment': process.env.MTN_MOMO_TARGET_ENV || 'sandbox',
                'Ocp-Apim-Subscription-Key': process.env.MTN_MOMO_SUBSCRIPTION_KEY
            },
            timeout: 15000
        }
    )

    return response.data
}

/* =========================================================
   AIRTEL MONEY
   Airtel Africa exposes merchant collection APIs through its
   developer portal. Base URL and credentials are configurable.
========================================================= */

let airtelTokenCache = { token: null, expiresAt: 0 }

async function airtelToken() {
    if (airtelTokenCache.token && Date.now() < airtelTokenCache.expiresAt) {
        return airtelTokenCache.token
    }

    const response = await axios.post(
        `${process.env.AIRTEL_BASE_URL}/auth/oauth2/token`,
        {
            client_id: process.env.AIRTEL_CLIENT_ID,
            client_secret: process.env.AIRTEL_CLIENT_SECRET,
            grant_type: 'client_credentials'
        },
        {
            headers: { 'Content-Type': 'application/json' },
            timeout: 15000
        }
    )

    airtelTokenCache = {
        token: response.data.access_token,
        expiresAt: Date.now() + ((response.data.expires_in || 3600) - 60) * 1000
    }

    return airtelTokenCache.token
}

async function startAirtelPayment({ amount, phone, referenceId }) {
    const token = await airtelToken()
    const target = normalizeRwPhone(phone)

    const response = await axios.post(
        `${process.env.AIRTEL_BASE_URL}/merchant/v1/payments/`,
        {
            reference: referenceId,
            subscriber: {
                country: 'RW',
                currency: 'RWF',
                msisdn: target
            },
            transaction: {
                amount: Number(amount),
                country: 'RW',
                currency: 'RWF',
                id: referenceId
            }
        },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                'X-Country': 'RW',
                'X-Currency': 'RWF'
            },
            timeout: 15000
        }
    )

    return {
        provider: 'AIRTEL_MONEY',
        referenceId,
        data: response.data
    }
}

/* =========================================================
   CARD CHECKOUT
   Never collect raw card number/CVV/PIN in this API.
   Use the hosted checkout URL supplied by your acquirer/gateway.
========================================================= */

async function startCardPayment({ amount, referenceId, orderId, phone }) {
    if (!process.env.CARD_CHECKOUT_URL) {
        throw new Error('CARD_CHECKOUT_URL is not configured')
    }

    // The actual provider SDK/API should create a hosted 3DS checkout.
    // This endpoint is intentionally provider-neutral.
    return {
        provider: 'CARD_GATEWAY',
        referenceId,
        checkoutUrl:
            `${process.env.CARD_CHECKOUT_URL}` +
            `?reference=${encodeURIComponent(referenceId)}` +
            `&amount=${encodeURIComponent(amount)}` +
            `&currency=RWF` +
            `&order=${encodeURIComponent(orderId)}` +
            `&phone=${encodeURIComponent(phone)}`
    }
}

/* =========================================================
   PAYMENT ORCHESTRATOR
========================================================= */

async function createPayment({ method, amount, phone, orderId, referenceId }) {
    if (method === 'MTN_MOMO') {
        return startMtnMomoPayment({
            amount,
            phone,
            orderId,
            referenceId
        })
    }

    if (method === 'AIRTEL_MONEY') {
        return startAirtelPayment({
            amount,
            phone,
            referenceId
        })
    }

    if (method === 'MASTERCARD' || method === 'VISA') {
        return startCardPayment({
            amount,
            referenceId,
            orderId,
            phone
        })
    }

    throw new Error('Unsupported payment method')
}


function encryptionKey() {
    return crypto.createHash('sha256')
        .update(process.env.DELIVERY_CODE_SECRET || process.env.JWT_SECRET)
        .digest()
}

function encryptDeliveryCode(code) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv)
    const encrypted = Buffer.concat([cipher.update(String(code), 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`
}

function decryptDeliveryCode(value) {
    const [ivB64, tagB64, dataB64] = String(value).split('.')
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'))
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'))
    return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8')
}

async function markPaymentSuccess(referenceId, providerTransactionId = null) {
    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        const [payments] = await connection.query(
            `SELECT * FROM payments WHERE reference = ? FOR UPDATE`,
            [referenceId]
        )

        if (!payments.length) {
            await connection.rollback()
            return null
        }

        const payment = payments[0]

        if (payment.status === PAYMENT.SUCCESS) {
            await connection.commit()
            return payment
        }

        await connection.query(
            `UPDATE payments
             SET status='SUCCESS', provider_transaction_id=?, paid_at=NOW()
             WHERE id=?`,
            [providerTransactionId, payment.id]
        )

        await connection.query(
            `UPDATE orders SET status='PAID'
             WHERE id=? AND status='PENDING_PAYMENT'`,
            [payment.order_id]
        )

        const [orders] = await connection.query(
            `SELECT o.id, o.delivery_phone, o.total_amount, d.customer_code_encrypted
             FROM orders o LEFT JOIN deliveries d ON d.order_id=o.id
             WHERE o.id=?`,
            [payment.order_id]
        )

        await connection.commit()

        if (orders.length) {
            await safeSMS(
                orders[0].delivery_phone,
                `Baby Doll: Payment received for order #${orders[0].id}. Amount: ${orders[0].total_amount} RWF. Your order is confirmed. Delivery PIN: ${decryptDeliveryCode(orders[0].customer_code_encrypted)}`
            )
        }

        return payment
    } catch (error) {
        await connection.rollback()
        throw error
    } finally {
        connection.release()
    }
}

/* =========================================================
   AUTH
========================================================= */

app.post('/signup', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body

        if (!username || !password || password.length < 8) {
            return res.status(400).json({
                message: 'Username and password are required. Password must be at least 8 characters.'
            })
        }

        const [exists] = await db.query(
            'SELECT id FROM users WHERE username=? LIMIT 1',
            [username]
        )

        if (exists.length) {
            return res.status(409).json({ message: 'Username already exists' })
        }

        const hash = await bcrypt.hash(password, 12)

        await db.query(
            `INSERT INTO users (username,password,role,image)
             VALUES (?,?,'user','user.png')`,
            [username, hash]
        )

        res.status(201).json({ message: 'User registered successfully' })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Registration failed' })
    }
})

app.post('/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body

        const [rows] = await db.query(
            `SELECT id,username,password,role,image,status
             FROM users WHERE username=? LIMIT 1`,
            [username]
        )

        if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) {
            return res.status(401).json({ message: 'Invalid username or password' })
        }

        const user = rows[0]
        if (user.status && user.status !== 'ACTIVE') {
            return res.status(403).json({ message: 'Account is not active' })
        }
        delete user.password
        authCookie(res, user)
        await audit(user.id, 'LOGIN', 'auth', user.id)

        res.json({ message: 'Login successful', user })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Login failed' })
    }
})

app.post('/logout', (req, res) => {
    res.clearCookie('access_token')
    res.json({ message: 'Logout successful' })
})

app.get('/user', requireAuth, async (req, res) => {
    const [rows] = await db.query(
        'SELECT id,username,role,image,status FROM users WHERE id=?',
        [req.user.id]
    )
    res.json({ user: rows[0] || null })
})

/* =========================================================
   ADMIN / WORKER MANAGEMENT
   All worker actions are protected by backend permissions.
========================================================= */

app.get('/admin/dashboard', requireAuth, requirePermission('dashboard:view'), async (req, res) => {
    try {
        const [[sales]] = await db.query(
            `SELECT COALESCE(SUM(total_amount),0) AS total_sales,
                    COUNT(*) AS total_orders
             FROM orders WHERE status <> 'CANCELLED'`
        )
        const [[customers]] = await db.query(
            `SELECT COUNT(*) AS total_customers FROM users WHERE role='user'`
        )
        const [[products]] = await db.query(
            `SELECT COUNT(*) AS total_products FROM products`
        )
        const [ordersByStatus] = await db.query(
            `SELECT status,COUNT(*) AS total FROM orders GROUP BY status ORDER BY status`
        )
        const [paymentsByMethod] = await db.query(
            `SELECT method,COUNT(*) AS total,SUM(amount) AS amount
             FROM payments WHERE status='SUCCESS' GROUP BY method`
        )
        const [monthlySales] = await db.query(
            `SELECT DATE_FORMAT(created_at,'%Y-%m') AS month,
                    SUM(total_amount) AS amount,COUNT(*) AS orders
             FROM orders WHERE status <> 'CANCELLED'
             GROUP BY DATE_FORMAT(created_at,'%Y-%m')
             ORDER BY month DESC LIMIT 12`
        )

        res.json({
            summary: {
                total_sales: Number(sales.total_sales),
                total_orders: Number(sales.total_orders),
                total_customers: Number(customers.total_customers),
                total_products: Number(products.total_products)
            },
            orders_by_status: ordersByStatus,
            payments_by_method: paymentsByMethod,
            monthly_sales: monthlySales
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Dashboard failed' })
    }
})

app.get('/admin/workers', requireAuth, requirePermission('worker:read'), async (req, res) => {
    const [workers] = await db.query(
        `SELECT id,username,role,image,status FROM users
         WHERE role IN ('admin','manager','employee') ORDER BY username`
    )
    res.json({ workers })
})

app.post('/admin/workers', requireAuth, requirePermission('worker:create'), async (req, res) => {
    try {
        const { username, password, role: workerRole, image } = req.body
        if (!username || !password || password.length < 8) {
            return res.status(400).json({ message: 'Username and password are required; password must be at least 8 characters.' })
        }
        if (!['manager', 'employee'].includes(workerRole)) {
            return res.status(400).json({ message: 'Worker role must be manager or employee' })
        }

        const [exists] = await db.query('SELECT id FROM users WHERE username=? LIMIT 1', [username])
        if (exists.length) return res.status(409).json({ message: 'Username already exists' })

        const hash = await bcrypt.hash(password, 12)
        const [result] = await db.query(
            `INSERT INTO users(username,password,role,image,status)
             VALUES(?,?,?,?,'ACTIVE')`,
            [username, hash, workerRole, image || 'user.png']
        )

        await audit(req.user.id, 'CREATE_WORKER', 'user', result.insertId, { role: workerRole })
        res.status(201).json({ message: 'Worker account created', worker_id: result.insertId })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Worker creation failed' })
    }
})

app.patch('/admin/workers/:id/status', requireAuth, requirePermission('worker:manage'), async (req, res) => {
    const status = String(req.body.status || '').toUpperCase()
    if (!['ACTIVE', 'SUSPENDED', 'DISABLED'].includes(status)) {
        return res.status(400).json({ message: 'Invalid worker status' })
    }

    const [result] = await db.query(
        `UPDATE users SET status=?
         WHERE id=? AND role IN ('manager','employee')`,
        [status, req.params.id]
    )
    if (!result.affectedRows) return res.status(404).json({ message: 'Worker not found' })

    await audit(req.user.id, 'CHANGE_WORKER_STATUS', 'user', req.params.id, { status })
    res.json({ message: 'Worker status updated' })
})

app.get('/admin/permissions', requireAuth, requirePermission('permission:manage'), async (req, res) => {
    const [permissions] = await db.query('SELECT id,name,description FROM permissions ORDER BY name')
    res.json({ permissions })
})

app.get('/admin/workers/:id/permissions', requireAuth, requirePermission('permission:manage'), async (req, res) => {
    const [rows] = await db.query(
        `SELECT p.id,p.name,p.description,COALESCE(up.allowed,0) AS allowed
         FROM permissions p
         LEFT JOIN user_permissions up ON up.permission_id=p.id AND up.user_id=?
         ORDER BY p.name`,
        [req.params.id]
    )
    res.json({ permissions: rows })
})

app.put('/admin/workers/:id/permissions', requireAuth, requirePermission('permission:manage'), async (req, res) => {
    const permissions = Array.isArray(req.body.permissions) ? req.body.permissions : []
    const connection = await db.getConnection()
    try {
        await connection.beginTransaction()
        const [worker] = await connection.query(
            `SELECT id,role FROM users WHERE id=? AND role IN ('manager','employee') FOR UPDATE`,
            [req.params.id]
        )
        if (!worker.length) {
            await connection.rollback()
            return res.status(404).json({ message: 'Worker not found' })
        }

        await connection.query('DELETE FROM user_permissions WHERE user_id=?', [req.params.id])
        for (const item of permissions) {
            const permissionName = typeof item === 'string' ? item : item.name
            const allowed = typeof item === 'string' ? true : item.allowed !== false
            const [p] = await connection.query('SELECT id FROM permissions WHERE name=? LIMIT 1', [permissionName])
            if (p.length) {
                await connection.query(
                    `INSERT INTO user_permissions(user_id,permission_id,allowed) VALUES(?,?,?)`,
                    [req.params.id, p[0].id, allowed ? 1 : 0]
                )
            }
        }
        await connection.commit()
        await audit(req.user.id, 'UPDATE_WORKER_PERMISSIONS', 'user', req.params.id, { permissions })
        res.json({ message: 'Worker permissions updated' })
    } catch (error) {
        await connection.rollback()
        console.error(error)
        res.status(500).json({ message: 'Permission update failed' })
    } finally {
        connection.release()
    }
})

app.get('/admin/audit-logs', requireAuth, requirePermission('audit:read'), async (req, res) => {
    const [rows] = await db.query(
        `SELECT a.*,u.username FROM audit_logs a
         LEFT JOIN users u ON u.id=a.user_id
         ORDER BY a.created_at DESC LIMIT 200`
    )
    res.json({ logs: rows })
})

/* =========================================================
   PRODUCTS / CATEGORY
========================================================= */

app.post('/category', requireAuth, requirePermission('category:create'), async (req, res) => {
    await db.query(
        'INSERT INTO category(name,image) VALUES(?,?)',
        [req.body.name, req.body.image || null]
    )
    await audit(req.user.id, 'CREATE_CATEGORY', 'category', null, { name: req.body.name })
    res.status(201).json({ message: 'Category added successfully' })
})

app.get('/category', async (req, res) => {
    const [rows] = await db.query('SELECT * FROM category ORDER BY name')
    res.json({ categories: rows })
})

app.post('/product', requireAuth, requirePermission('product:create'), async (req, res) => {
    const { name, category, description, price, image } = req.body

    await db.query(
        `INSERT INTO products
         (name,category,user_id,date,description,price,image)
         VALUES(?,?,?,NOW(),?,?,?)`,
        [name, category, req.user.id, description || '', price, image || null]
    )

    await audit(req.user.id, 'CREATE_PRODUCT', 'product', null, { name })
    res.status(201).json({ message: 'Product added successfully' })
})

app.get('/product', async (req, res) => {
    const [rows] = await db.query('SELECT * FROM products ORDER BY date DESC')
    res.json({ products: rows })
})

app.get('/product/:id', async (req, res) => {
    const [rows] = await db.query(
        `SELECT p.*,u.username
         FROM products p LEFT JOIN users u ON u.id=p.user_id
         WHERE p.id=?`,
        [req.params.id]
    )

    if (!rows.length) return res.status(404).json({ message: 'Product not found' })
    res.json({ product: rows[0] })
})

app.get('/search', async (req, res) => {
    const { name, category } = req.query
    let sql = 'SELECT * FROM products WHERE 1=1'
    const params = []

    if (name) {
        sql += ' AND name LIKE ?'
        params.push(`%${name}%`)
    }

    if (category) {
        sql += ' AND category=?'
        params.push(category)
    }

    sql += ' ORDER BY date DESC'

    const [rows] = await db.query(sql, params)
    res.json({ products: rows })
})

/* =========================================================
   CART
========================================================= */

app.post('/cart', requireAuth, requirePermission('cart:write'), async (req, res) => {
    const quantity = Number(req.body.quantity)

    if (!Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({ message: 'Invalid quantity' })
    }

    await db.query(
        `INSERT INTO cart(user_id,product_id,quantity)
         VALUES(?,?,?)
         ON DUPLICATE KEY UPDATE quantity=quantity+VALUES(quantity)`,
        [req.user.id, req.body.product_id, quantity]
    )

    res.status(201).json({ message: 'Product added to cart' })
})

app.get('/cart', requireAuth, requirePermission('cart:read'), async (req, res) => {
    const [rows] = await db.query(
        `SELECT c.*,p.name,p.price,p.image
         FROM cart c JOIN products p ON p.id=c.product_id
         WHERE c.user_id=?`,
        [req.user.id]
    )

    res.json({ cart: rows })
})

/* =========================================================
   CHECKOUT
========================================================= */

app.post('/checkout', requireAuth, requirePermission('order:create'), async (req, res) => {
    const connection = await db.getConnection()

    try {
        const { address, phone, payment_method } = req.body
        const allowed = ['MTN_MOMO', 'AIRTEL_MONEY', 'MASTERCARD', 'VISA']

        if (!allowed.includes(payment_method)) {
            return res.status(400).json({ message: 'Unsupported payment method' })
        }

        const normalizedPhone = normalizeRwPhone(phone)

        await connection.beginTransaction()

        const [cart] = await connection.query(
            `SELECT c.product_id,c.quantity,p.price
             FROM cart c JOIN products p ON p.id=c.product_id
             WHERE c.user_id=?`,
            [req.user.id]
        )

        if (!cart.length) {
            await connection.rollback()
            return res.status(400).json({ message: 'Cart is empty' })
        }

        const total = cart.reduce(
            (sum, item) => sum + Number(item.price) * Number(item.quantity),
            0
        )

        const [orderResult] = await connection.query(
            `INSERT INTO orders
             (user_id,total_amount,currency,status,delivery_address,delivery_phone)
             VALUES(?,?,'RWF','PENDING_PAYMENT',?,?)`,
            [req.user.id, total, address, normalizedPhone]
        )

        const orderId = orderResult.insertId
        const paymentReference = reference()

        for (const item of cart) {
            await connection.query(
                `INSERT INTO order_items(order_id,product_id,quantity,unit_price)
                 VALUES(?,?,?,?)`,
                [orderId, item.product_id, item.quantity, item.price]
            )
        }

        await connection.query(
            `INSERT INTO payments
             (order_id,user_id,reference,method,amount,currency,status,provider)
             VALUES(?,?,?,?,?,'RWF','PENDING','PENDING')`,
            [
                orderId,
                req.user.id,
                paymentReference,
                payment_method,
                total
            ]
        )

        /*
         * Store delivery code only as a hash.
         * The customer receives the code by SMS after payment succeeds.
         */
        const customerCode = String(crypto.randomInt(100000, 1000000))

        await connection.query(
            `INSERT INTO deliveries
             (order_id,customer_id,status,customer_accepted,courier_accepted,customer_code_hash,customer_code_encrypted)
             VALUES(?,?, 'PENDING',0,0,?,?)`,
            [orderId, req.user.id, deliveryCodeHash(customerCode), encryptDeliveryCode(customerCode)]
        )

        await connection.query('DELETE FROM cart WHERE user_id=?', [req.user.id])
        await connection.commit()

        try {
            const payment = await createPayment({
                method: payment_method,
                amount: total,
                phone: normalizedPhone,
                orderId,
                referenceId: paymentReference
            })

            await db.query(
                `UPDATE payments
                 SET provider=?,checkout_url=?
                 WHERE reference=?`,
                [
                    payment.provider,
                    payment.checkoutUrl || null,
                    paymentReference
                ]
            )

            /*
             * For MTN/Airtel the customer receives the provider's
             * payment prompt. The delivery code is NOT sent yet.
             */
            await safeSMS(
                normalizedPhone,
                `Baby Doll: Order #${orderId} created. Payment of ${total} RWF is pending.`
            )

            res.status(201).json({
                message: 'Payment started',
                order_id: orderId,
                payment_reference: paymentReference,
                payment_method,
                status: PAYMENT.PENDING,
                checkout_url: payment.checkoutUrl || null
            })
        } catch (error) {
            await db.query(
                `UPDATE payments SET status='FAILED' WHERE reference=?`,
                [paymentReference]
            )

            await db.query(
                `UPDATE orders SET status='CANCELLED'
                 WHERE id=? AND status='PENDING_PAYMENT'`,
                [orderId]
            )

            console.error('Payment start error:', error.response?.data || error.message)

            res.status(502).json({
                message: 'Payment provider could not start the transaction',
                order_id: orderId
            })
        }
    } catch (error) {
        try { await connection.rollback() } catch {}
        console.error(error)
        res.status(500).json({ message: 'Checkout failed' })
    } finally {
        connection.release()
    }
})

/* =========================================================
   PROVIDER WEBHOOKS
========================================================= */

function validWebhookSecret(req) {
    const expected = process.env.PAYMENT_WEBHOOK_SECRET
    if (!expected) return true

    const supplied = req.headers['x-payment-signature']
    if (!supplied) return false

    const digest = crypto
        .createHmac('sha256', expected)
        .update(JSON.stringify(req.body))
        .digest('hex')

    return supplied.length === digest.length &&
        crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(digest))
}

/*
Generic gateway webhook for Airtel/card provider.
Configure your provider to call this URL after payment.
*/
app.post('/payments/webhook', async (req, res) => {
    try {
        if (!validWebhookSecret(req)) {
            return res.status(401).json({ message: 'Invalid webhook signature' })
        }

        const referenceId =
            req.body.reference ||
            req.body.referenceId ||
            req.body.transaction?.id

        const status = String(
            req.body.status ||
            req.body.transaction?.status ||
            ''
        ).toUpperCase()

        if (!referenceId) {
            return res.status(400).json({ message: 'Missing payment reference' })
        }

        if (['SUCCESS', 'SUCCESSFUL', 'COMPLETED', 'TS'].includes(status)) {
            await markPaymentSuccess(
                referenceId,
                req.body.transaction_id ||
                req.body.provider_transaction_id ||
                null
            )
        } else if (['FAILED', 'FAILURE', 'CANCELLED', 'TF'].includes(status)) {
            await db.query(
                `UPDATE payments SET status='FAILED'
                 WHERE reference=? AND status='PENDING'`,
                [referenceId]
            )
            await db.query(
                `UPDATE orders o JOIN payments p ON p.order_id=o.id
                 SET o.status='CANCELLED'
                 WHERE p.reference=? AND o.status='PENDING_PAYMENT'`,
                [referenceId]
            )
        }

        res.json({ received: true })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Webhook processing failed' })
    }
})

/*
MTN MoMo status endpoint.
Use this when callback delivery is unavailable or as a polling fallback.
*/
app.get('/payments/mtn/:referenceId/status', requireAuth, requirePermission('payment:read'), async (req, res) => {
    try {
        const [payments] = await db.query(
            `SELECT p.*,o.user_id,o.delivery_phone
             FROM payments p JOIN orders o ON o.id=p.order_id
             WHERE p.reference=?`,
            [req.params.referenceId]
        )

        if (!payments.length) return res.status(404).json({ message: 'Payment not found' })

        const payment = payments[0]

        if (payment.user_id !== req.user.id && !(await hasPermission(req.user, 'payment:read_all'))) {
            return res.status(403).json({ message: 'Access denied' })
        }

        const providerStatus = await getMtnMomoStatus(req.params.referenceId)
        const status = String(providerStatus.status || '').toUpperCase()

        if (status === 'SUCCESSFUL') {
            await markPaymentSuccess(
                req.params.referenceId,
                providerStatus.financialTransactionId || null
            )
        } else if (status === 'FAILED') {
            await db.query(
                `UPDATE payments SET status='FAILED'
                 WHERE reference=? AND status='PENDING'`,
                [req.params.referenceId]
            )
        }

        res.json({
            reference: req.params.referenceId,
            provider_status: providerStatus.status
        })
    } catch (error) {
        console.error(error.response?.data || error.message)
        res.status(502).json({ message: 'Unable to check MTN MoMo payment' })
    }
})

/* =========================================================
   DELIVERY
========================================================= */

app.post('/deliveries/:id/assign', requireAuth, requirePermission('delivery:assign'), async (req, res) => {
    const courierId = req.body.courier_id

    const [couriers] = await db.query(
        `SELECT id,username FROM users
         WHERE id=? AND role='employee'`,
        [courierId]
    )

    if (!couriers.length) {
        return res.status(400).json({ message: 'Invalid courier' })
    }

    const [result] = await db.query(
        `UPDATE deliveries d
         JOIN orders o ON o.id=d.order_id
         SET d.courier_id=?,d.status='ASSIGNED'
         WHERE d.id=? AND o.status='PAID'`,
        [courierId, req.params.id]
    )

    if (!result.affectedRows) {
        return res.status(400).json({ message: 'Order must be paid before assignment' })
    }

    const [rows] = await db.query(
        `SELECT o.id,o.delivery_phone
         FROM deliveries d JOIN orders o ON o.id=d.order_id
         WHERE d.id=?`,
        [req.params.id]
    )

    if (rows.length) {
        await safeSMS(
            rows[0].delivery_phone,
            `Baby Doll: Courier ${couriers[0].username} has been assigned to order #${rows[0].id}.`
        )
    }

    res.json({ message: 'Delivery assigned' })
})

app.post('/deliveries/:id/pickup', requireAuth, requirePermission('delivery:pickup'), async (req, res) => {
    const [result] = await db.query(
        `UPDATE deliveries
         SET status='PICKED_UP'
         WHERE id=? AND courier_id=? AND status='ASSIGNED'`,
        [req.params.id, req.user.id]
    )

    if (!result.affectedRows) {
        return res.status(400).json({ message: 'Delivery is not assigned to you' })
    }

    res.json({ message: 'Package picked up' })
})

app.post('/deliveries/:id/out-for-delivery', requireAuth, requirePermission('delivery:out_for_delivery'), async (req, res) => {
    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        const [result] = await connection.query(
            `UPDATE deliveries
             SET status='OUT_FOR_DELIVERY'
             WHERE id=? AND courier_id=? AND status='PICKED_UP'`,
            [req.params.id, req.user.id]
        )

        if (!result.affectedRows) {
            await connection.rollback()
            return res.status(400).json({ message: 'Delivery cannot start yet' })
        }

        await connection.query(
            `UPDATE orders o JOIN deliveries d ON d.order_id=o.id
             SET o.status='OUT_FOR_DELIVERY'
             WHERE d.id=? AND o.status='PAID'`,
            [req.params.id]
        )

        const [rows] = await connection.query(
            `SELECT o.id,o.delivery_phone,d.customer_code_hash
             FROM deliveries d JOIN orders o ON o.id=d.order_id
             WHERE d.id=?`,
            [req.params.id]
        )

        await connection.commit()

        /*
         * We cannot recover the original customer code from the hash.
         * Therefore, production systems should generate the code when
         * payment succeeds and store/send it through a separate workflow.
         * This route only sends a delivery-start message.
         */
        if (rows.length) {
            await safeSMS(
                rows[0].delivery_phone,
                `Baby Doll: Order #${rows[0].id} is out for delivery. Please be ready to confirm receipt.`
            )
        }

        res.json({ message: 'Delivery is out for delivery' })
    } catch (error) {
        await connection.rollback()
        res.status(500).json({ message: 'Failed to update delivery' })
    } finally {
        connection.release()
    }
})

/*
Customer confirmation uses a one-time delivery PIN.
For usability, this sample exposes the PIN through a protected
endpoint for the customer. In production you can send it by SMS
at the PAID/READY stage and never return it from the API.
*/
app.post('/deliveries/:id/customer-confirm', requireAuth, requirePermission('delivery:customer_confirm'), async (req, res) => {
    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        const [rows] = await connection.query(
            `SELECT d.*,o.user_id
             FROM deliveries d JOIN orders o ON o.id=d.order_id
             WHERE d.id=? AND o.user_id=? FOR UPDATE`,
            [req.params.id, req.user.id]
        )

        if (!rows.length) {
            await connection.rollback()
            return res.status(404).json({ message: 'Delivery not found' })
        }

        const delivery = rows[0]

        if (![DELIVERY.OUT_FOR_DELIVERY, DELIVERY.CUSTOMER_ACCEPTED].includes(delivery.status)) {
            await connection.rollback()
            return res.status(400).json({ message: 'Delivery is not ready for confirmation' })
        }

        const supplied = deliveryCodeHash(req.body.code || '')

        if (
            !delivery.customer_code_hash ||
            supplied !== delivery.customer_code_hash
        ) {
            await connection.rollback()
            return res.status(400).json({ message: 'Invalid delivery code' })
        }

        await connection.query(
            `UPDATE deliveries
             SET customer_accepted=1,customer_accepted_at=NOW()
             WHERE id=?`,
            [req.params.id]
        )

        const [state] = await connection.query(
            `SELECT customer_accepted,courier_accepted
             FROM deliveries WHERE id=?`,
            [req.params.id]
        )

        let completed = false

        if (state[0].customer_accepted && state[0].courier_accepted) {
            await connection.query(
                `UPDATE deliveries
                 SET status='COMPLETED',completed_at=NOW()
                 WHERE id=?`,
                [req.params.id]
            )

            await connection.query(
                `UPDATE orders o JOIN deliveries d ON d.order_id=o.id
                 SET o.status='DELIVERED'
                 WHERE d.id=?`,
                [req.params.id]
            )

            completed = true
        } else {
            await connection.query(
                `UPDATE deliveries SET status='CUSTOMER_ACCEPTED' WHERE id=?`,
                [req.params.id]
            )
        }

        const [order] = await connection.query(
            `SELECT o.id,o.delivery_phone FROM deliveries d
             JOIN orders o ON o.id=d.order_id
             WHERE d.id=?`,
            [req.params.id]
        )

        await connection.commit()

        if (completed && order.length) {
            await safeSMS(
                order[0].delivery_phone,
                `Baby Doll: Order #${order[0].id} has been delivered and accepted by both customer and courier.`
            )
        }

        res.json({
            message: completed
                ? 'Delivery completed by both parties'
                : 'Customer confirmation recorded',
            completed
        })
    } catch (error) {
        await connection.rollback()
        res.status(500).json({ message: 'Customer confirmation failed' })
    } finally {
        connection.release()
    }
})

app.post('/deliveries/:id/courier-confirm', requireAuth, requirePermission('delivery:courier_confirm'), async (req, res) => {
    const connection = await db.getConnection()

    try {
        await connection.beginTransaction()

        const [rows] = await connection.query(
            `SELECT d.*,o.delivery_phone,o.id AS order_id
             FROM deliveries d JOIN orders o ON o.id=d.order_id
             WHERE d.id=? AND d.courier_id=? FOR UPDATE`,
            [req.params.id, req.user.id]
        )

        if (!rows.length) {
            await connection.rollback()
            return res.status(404).json({ message: 'Delivery not found' })
        }

        await connection.query(
            `UPDATE deliveries
             SET courier_accepted=1,courier_accepted_at=NOW()
             WHERE id=?`,
            [req.params.id]
        )

        const [state] = await connection.query(
            `SELECT customer_accepted,courier_accepted
             FROM deliveries WHERE id=?`,
            [req.params.id]
        )

        let completed = false

        if (state[0].customer_accepted && state[0].courier_accepted) {
            await connection.query(
                `UPDATE deliveries
                 SET status='COMPLETED',completed_at=NOW()
                 WHERE id=?`,
                [req.params.id]
            )

            await connection.query(
                `UPDATE orders o JOIN deliveries d ON d.order_id=o.id
                 SET o.status='DELIVERED'
                 WHERE d.id=?`,
                [req.params.id]
            )

            completed = true
        } else {
            await connection.query(
                `UPDATE deliveries SET status='COURIER_ACCEPTED' WHERE id=?`,
                [req.params.id]
            )
        }

        await connection.commit()

        if (completed) {
            await safeSMS(
                rows[0].delivery_phone,
                `Baby Doll: Order #${rows[0].order_id} has been delivered and accepted by both parties.`
            )
        }

        res.json({
            message: completed
                ? 'Delivery completed by both parties'
                : 'Courier confirmation recorded',
            completed
        })
    } catch (error) {
        await connection.rollback()
        res.status(500).json({ message: 'Courier confirmation failed' })
    } finally {
        connection.release()
    }
})

app.get('/deliveries', requireAuth, requirePermission('delivery:read'), async (req, res) => {
    let sql = `
        SELECT d.*,o.total_amount,o.delivery_address,o.delivery_phone,
               u.username AS customer_name,
               c.username AS courier_name
        FROM deliveries d
        JOIN orders o ON o.id=d.order_id
        JOIN users u ON u.id=d.customer_id
        LEFT JOIN users c ON c.id=d.courier_id
    `
    const params = []

    if (req.user.role === 'user') {
        sql += ' WHERE d.customer_id=?'
        params.push(req.user.id)
    } else if (req.user.role === 'employee') {
        sql += ' WHERE d.courier_id=?'
        params.push(req.user.id)
    }

    sql += ' ORDER BY d.created_at DESC'

    const [rows] = await db.query(sql, params)
    res.json({ deliveries: rows })
})

app.get('/orders/:id', requireAuth, requireAnyPermission('order:read_own','order:read_all'), async (req, res) => {
    const [orders] = await db.query(
        `SELECT o.*,p.reference,p.method,p.amount,p.currency,p.status AS payment_status,
                p.provider_transaction_id,p.paid_at,
                d.status AS delivery_status,d.courier_id,
                d.customer_accepted,d.courier_accepted
         FROM orders o
         LEFT JOIN payments p ON p.order_id=o.id
         LEFT JOIN deliveries d ON d.order_id=o.id
         WHERE o.id=?`,
        [req.params.id]
    )

    if (!orders.length) return res.status(404).json({ message: 'Order not found' })

    if (orders[0].user_id !== req.user.id && !(await hasPermission(req.user, 'order:read_all'))) {
        return res.status(403).json({ message: 'Access denied' })
    }

    const [items] = await db.query(
        `SELECT oi.*,p.name,p.image
         FROM order_items oi JOIN products p ON p.id=oi.product_id
         WHERE oi.order_id=?`,
        [req.params.id]
    )

    res.json({ order: orders[0], items })
})

app.post('/rating', requireAuth, requirePermission('review:create'), async (req, res) => {
    const rating = Number(req.body.rating)

    if (rating < 1 || rating > 5) {
        return res.status(400).json({ message: 'Rating must be 1 to 5' })
    }

    await db.query(
        `INSERT INTO ratings(user_id,product_id,rating)
         VALUES(?,?,?)
         ON DUPLICATE KEY UPDATE rating=VALUES(rating)`,
        [req.user.id, req.body.product_id, rating]
    )

    res.json({ message: 'Rating saved successfully' })
})

app.get('/rating/:product_id', async (req, res) => {
    const [rows] = await db.query(
        `SELECT AVG(rating) AS average_rating
         FROM ratings WHERE product_id=?`,
        [req.params.product_id]
    )

    res.json({ average_rating: rows[0].average_rating })
})

app.use((err, req, res, next) => {
    console.error(err)
    res.status(500).json({ message: 'Internal server error' })
})

app.listen(PORT, () => {
    console.log(`Baby Doll API running on port ${PORT}`)
})
