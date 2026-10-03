const prisma = require('./backend/config/database');

async function test() {
  try {
    const users = await prisma.user.findMany({
      include: {
        organizations: {
          include: {
            organization: true
          }
        }
      }
    });
    console.log('Total users in DB:', users.length);
    users.forEach(u => {
      console.log(`- ID: ${u.id}, Email: ${u.email}, Name: ${u.firstName} ${u.lastName}, Orgs: ${u.organizations.length}`);
    });
  } catch (err) {
    console.error('Error fetching users:', err);
  } finally {
    await prisma.$disconnect();
  }
}

test();
