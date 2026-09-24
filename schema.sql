CREATE DATABASE IF NOT EXISTS baby_doll;
USE baby_doll;

ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL;

CREATE TABLE IF NOT EXISTS orders (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    total_amount DECIMAL(15,2) NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'RWF',
    status ENUM('PENDING_PAYMENT','PAID','READY_FOR_DELIVERY','OUT_FOR_DELIVERY','DELIVERED','CANCELLED')
        NOT NULL DEFAULT 'PENDING_PAYMENT',
    delivery_address VARCHAR(500) NOT NULL,
    delivery_phone VARCHAR(30) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_orders_user(user_id),
    INDEX idx_orders_status(status),
    CONSTRAINT fk_orders_user FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS order_items (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT UNSIGNED NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(15,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_order_items_order(order_id),
    CONSTRAINT fk_order_items_order FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT UNSIGNED NOT NULL,
    user_id INT NOT NULL,
    reference VARCHAR(100) NOT NULL UNIQUE,
    provider_transaction_id VARCHAR(150),
    provider VARCHAR(80) NOT NULL,
    method ENUM('MTN_MOMO','AIRTEL_MONEY','MASTERCARD','VISA') NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'RWF',
    status ENUM('PENDING','SUCCESS','FAILED','CANCELLED') NOT NULL DEFAULT 'PENDING',
    checkout_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    paid_at TIMESTAMP NULL,
    INDEX idx_payments_order(order_id),
    INDEX idx_payments_status(status),
    CONSTRAINT fk_payments_order FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
    CONSTRAINT fk_payments_user FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS deliveries (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT UNSIGNED NOT NULL UNIQUE,
    customer_id INT NOT NULL,
    courier_id INT NULL,
    status ENUM('PENDING','ASSIGNED','PICKED_UP','OUT_FOR_DELIVERY','CUSTOMER_ACCEPTED','COURIER_ACCEPTED','COMPLETED','FAILED')
        NOT NULL DEFAULT 'PENDING',
    customer_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    courier_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    customer_code_hash CHAR(64) NOT NULL,
    customer_code_encrypted TEXT NOT NULL,
    customer_accepted_at TIMESTAMP NULL,
    courier_accepted_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_delivery_customer(customer_id),
    INDEX idx_delivery_courier(courier_id),
    INDEX idx_delivery_status(status),
    CONSTRAINT fk_delivery_order FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
    CONSTRAINT fk_delivery_customer FOREIGN KEY(customer_id) REFERENCES users(id),
    CONSTRAINT fk_delivery_courier FOREIGN KEY(courier_id) REFERENCES users(id)
);

ALTER TABLE cart ADD UNIQUE KEY uq_cart_user_product(user_id,product_id);
ALTER TABLE ratings ADD UNIQUE KEY uq_rating_user_product(user_id,product_id);

/* =========================================================
   RBAC / WORKER TASK PERMISSIONS
   Authentication identifies the worker; permissions decide
   which tasks that worker can perform.
========================================================= */

ALTER TABLE users ADD COLUMN status ENUM('ACTIVE','SUSPENDED','DISABLED') NOT NULL DEFAULT 'ACTIVE';

CREATE TABLE IF NOT EXISTS permissions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255) NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role VARCHAR(50) NOT NULL,
    permission_id INT UNSIGNED NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY(role,permission_id),
    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_permissions (
    user_id INT NOT NULL,
    permission_id INT UNSIGNED NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY(user_id,permission_id),
    CONSTRAINT fk_user_permissions_user
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_permissions_permission
        FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    resource_id VARCHAR(100) NULL,
    details JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user(user_id),
    INDEX idx_audit_created(created_at),
    CONSTRAINT fk_audit_user
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

INSERT IGNORE INTO permissions(name,description) VALUES
('dashboard:view','View business dashboard and analytics'),
('product:create','Create products'),
('product:read','View product management data'),
('product:update','Update products'),
('product:delete','Delete products'),
('category:create','Create categories'),
('category:update','Update categories'),
('category:delete','Delete categories'),
('cart:read','View own shopping cart'),
('cart:write','Add or update own shopping cart'),
('order:create','Create a customer order'),
('order:read_own','View own orders'),
('order:read_all','View all customer orders'),
('order:update','Update order workflow'),
('order:cancel','Cancel orders'),
('payment:read','View own payment status'),
('payment:read_all','View payment information for all orders'),
('payment:manage','Manage payment records'),
('delivery:read','View permitted deliveries'),
('delivery:assign','Assign deliveries to couriers'),
('delivery:pickup','Mark assigned delivery as picked up'),
('delivery:out_for_delivery','Start delivery'),
('delivery:customer_confirm','Record customer delivery confirmation'),
('delivery:courier_confirm','Record courier delivery confirmation'),
('review:create','Create or update product reviews'),
('user:read','View users/customers'),
('user:manage','Manage customer accounts'),
('worker:read','View worker accounts'),
('worker:create','Create manager/employee accounts'),
('worker:manage','Activate, suspend or disable workers'),
('permission:manage','Grant or revoke worker permissions'),
('audit:read','View security and administrative audit logs'),
('store:settings','Manage store settings'),
('sms:manage','Manage SMS configuration/logs'),
('report:view','View business reports');

/* Default task sets. Direct user_permissions can further customize a worker. */
INSERT IGNORE INTO role_permissions(role,permission_id,allowed)
SELECT 'manager',id,1 FROM permissions WHERE name IN (
    'dashboard:view','product:create','product:read','product:update',
    'category:create','cart:read','order:read_all','order:update',
    'payment:read_all','delivery:read','delivery:assign','delivery:out_for_delivery',
    'delivery:courier_confirm','user:read','report:view'
);

INSERT IGNORE INTO role_permissions(role,permission_id,allowed)
SELECT 'employee',id,1 FROM permissions WHERE name IN (
    'delivery:read','delivery:pickup','delivery:out_for_delivery',
    'delivery:courier_confirm'
);

INSERT IGNORE INTO role_permissions(role,permission_id,allowed)
SELECT 'user',id,1 FROM permissions WHERE name IN (
    'cart:read','cart:write','order:create','order:read_own',
    'payment:read','delivery:read','delivery:customer_confirm','review:create'
);

INSERT IGNORE INTO role_permissions(role,permission_id,allowed)
SELECT 'admin',id,1 FROM permissions;
