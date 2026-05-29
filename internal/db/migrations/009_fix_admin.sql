-- Fix default admin email and reset password to: ApexAegis@2026!
UPDATE system_mgmt.users
SET
    email         = 'admin@apexaegis.app',
    password_hash = '$2a$12$vOYL1ctN71LpjemdG8.qJe4.QgZcgHiNANJWF.oLETDxkqhYPJBAm'
WHERE id = 'b0000000-0000-0000-0000-000000000001';
