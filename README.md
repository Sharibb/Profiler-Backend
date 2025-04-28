# Deus API

This is the backend API for Sigh, using Express.js and PostgreSQL for all data storage including sessions.

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file with the following variables:
   ```
   PORT=3000
   DATABASE_URL=postgresql://username:password@hostname:port/database?sslmode=require
   SESSION_SECRET=your-secure-session-secret
   JWT_SECRET=your-secure-jwt-secret
   NODE_ENV=development
   ```

3. Make sure PostgreSQL is running and accessible with the provided connection string.

4. The application automatically creates the session table if it doesn't exist.

## Running the Application

### Development
```
npm run dev
```

### Production
```
npm start
```

## Session Storage

Sessions are stored in PostgreSQL using the `connect-pg-simple` package. The session configuration includes:
- Table name: `session`
- Session lifetime: 24 hours
- Secure cookies in production environment

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and create a session
- `POST /api/auth/logout` - Logout and destroy session
- `GET /api/auth/session` - Check session validity
- `POST /api/auth/forgot-password` - Request password reset

### Notes
- `GET /api/notes` - Get all notes for logged-in user
- `POST /api/notes` - Create or update a note
- `DELETE /api/notes/:id` - Delete a note

### Profiles
- `GET /api/hacking-profiles` - Get hacking profiles
- `POST /api/connect-platform` - Connect a hacking platform
- `POST /api/disconnect-platform` - Disconnect a hacking platform
- `GET /api/social-profiles` - Get social profiles
- `POST /api/connect-social` - Connect a social platform
- `POST /api/disconnect-social` - Disconnect a social platform

### TryHackMe Integration
- `GET /api/tryhackme/rank/:username` - Get TryHackMe rank
- `GET /api/tryhackme/badges/:username` - Get TryHackMe badges
- `GET /api/tryhackme/rooms/:username` - Get completed rooms count 