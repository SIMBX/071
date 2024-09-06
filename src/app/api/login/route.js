import { NextResponse } from "next/server";
import { Client } from "pg";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect();

export async function POST(request) {
  try {
    const { username, password } = await request.json();

    console.log('Received username:', username);
    console.log('Received password:', password);

    // ค้นหาผู้ใช้ในฐานข้อมูล
    const res = await client.query('SELECT * FROM tbl_users WHERE username = $1', [username]);

    if (res.rows.length === 0) {
      console.error('User not found:', username);
      return new NextResponse(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const user = res.rows[0];
    console.log('Found user:', user);

    // ตรวจสอบรหัสผ่าน
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      console.error('Invalid password for user:', username);
      return new NextResponse(JSON.stringify({ error: 'Invalid password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // สร้าง JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

    return new NextResponse(JSON.stringify({ message: 'Login successful', token }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Login error:', error);
    return new NextResponse(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
