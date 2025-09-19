import { db } from '#config/database.js';
import { user } from '#models/user.model.js';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcrypt';
import logger from '#config/logger.js';

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (error) {
    logger.error('Error hashing password', error);
    throw new Error('Error hashing password');
  }
};


export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    logger.error('Error comparing password', error);
    throw new Error('Error comparing password');
  }
};



export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db
      .select()
      .from(user)
      .where(eq(user.email, email))
      .limit(1);

    if (existingUser.length > 0) {
      throw new Error('User with this email already exists');
    }

    const hashedPassword = await hashPassword(password);

    const [newUser] = await db
      .insert(user)
      .values({ name, email, password: hashedPassword, role })
      .returning({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      });

    logger.info(`User created successfully: ${email}`);
    return newUser;

  } catch (error) {
    logger.error('Error creating user', error);
    throw new Error('Error creating user');
  }
};


export const authenticateUser = async ({ email, password }) => {
  try {
    const [existingUser ]= await db
      .select()
      .from(user)
      .where(eq(user.email, email))
      .limit(1);

    if (!existingUser) {
      throw new Error('User not found');
    }

    const isPasswordValid = await comparePassword(password, existingUser.password);

    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    logger.info(`User ${existingUser.email} authenticated successfully`);
    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      createdAt: existingUser.createdAt,
    };
  } catch (error) {
    logger.error('Error authenticating user', error);
    throw new Error('Error authenticating user');
  }


};
