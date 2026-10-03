const AuthService = require('./backend/services/auth.service');
const prisma = require('./backend/config/database');

async function testLogin() {
  try {
    console.log('Testing login for operator@cybersploi.io ...');
    const res = await AuthService.login('operator@cybersploi.io', 'Operator2024!');
    console.log('Login SUCCESS! Token prefix:', res.accessToken?.slice(0, 15));
  } catch (err) {
    console.error('Login Error:', err);
  } finally {
    await prisma.$disconnect();
  }
}

testLogin();
