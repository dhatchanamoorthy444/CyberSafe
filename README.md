# CyberSafe — Explainable URL & QR Risk Screening

An offline security engine that analyzes URLs, domains, IPs, hashes, and QR-derived content through deterministic pattern detection and transparent evidence chains.

## Architecture

- **Frontend**: Vanilla HTML/CSS/JS with Vite (deployed on Vercel)
- **Backend**: FastAPI (deployed on Render)
- **Database**: Supabase PostgreSQL
- **Analysis Engine**: Python (offline, deterministic)

## Deployment Guide

### 1. Deploy Backend to Render

1. Create a new Web Service on [Render](https://render.com)
2. Connect your GitHub repository
3. Configure the service:
   - **Name**: `cybersafe-api` (or your choice)
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Free

4. Add Environment Variables in Render:
   ```
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_KEY=your-supabase-service-role-key
   GROQ_API_KEY=your-groq-key (optional)
   VIRUSTOTAL_API_KEY=your-virustotal-key (optional)
   ```

5. Deploy and note your Render URL (e.g., `https://cybersafe-api.onrender.com`)

### 2. Set Up Supabase Database

1. Go to [Supabase Dashboard](https://supabase.com/dashboard)
2. Create a new project
3. Copy your Project URL and service role key
4. In SQL Editor, run the schema from `supabase/schema.sql`
5. Verify tables were created: `scan_history`, `scan_events`, `profiles`, `trusted_domains`

### 3. Deploy Frontend to Vercel

1. Go to [Vercel Dashboard](https://vercel.com)
2. Import your GitHub repository
3. Vercel should auto-detect the configuration from `vercel.json`
4. Add Environment Variable:
   ```
   VITE_API_URL=https://cybersafe-api.onrender.com
   ```
   (Replace with your actual Render backend URL)

5. Deploy

### 4. Update Backend CORS

After deployment, update `backend/app/main.py` line 30 to include your actual Vercel URL:
```python
allow_origins=[
    "https://your-actual-app.vercel.app",  # Update this
    "*"  # Remove in production
],
```

Then redeploy on Render.

## Local Development

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Access at `http://localhost:8000`
API docs at `http://localhost:8000/docs`

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Access at `http://localhost:3000`

## Environment Variables

### Backend (Render)
- `SUPABASE_URL`: Your Supabase project URL
- `SUPABASE_KEY`: Supabase service role key (keep secret)
- `GROQ_API_KEY`: Optional - for AI explanations
- `VIRUSTOTAL_API_KEY`: Optional - for threat intelligence

### Frontend (Vercel)
- `VITE_API_URL`: Your Render backend URL

## Security Features

- **Offline Analysis**: No network calls during URL parsing
- **Hash Storage**: Only SHA-256 hashes stored, never full suspicious URLs
- **Row Level Security**: Supabase RLS policies protect user data
- **CORS Protection**: Backend restricts allowed origins
- **No Auto-Navigation**: Never visits suspicious URLs

## API Endpoints

- `GET /health` - Health check
- `GET /` - API info
- `POST /api/analyze` - Analyze URL (same as `/scan`)
  ```json
  {
    "url": "https://example.com"
  }
  ```

## Testing

Test the deployment:
1. Open your Vercel URL
2. Submit a test URL: `https://google.com@evil.example/login`
3. Verify the analysis shows `@` deception detection
4. Check Supabase table `scan_history` for the stored hash

## Troubleshooting

### "Network error" in frontend
- Check `VITE_API_URL` is set in Vercel
- Verify Render backend is running (check `/health`)
- Check browser console for CORS errors

### Backend won't start on Render
- Check Render logs for import errors
- Verify `requirements.txt` includes all dependencies
- Ensure `PORT` environment variable is used correctly

### Supabase connection fails
- Verify `SUPABASE_URL` and `SUPABASE_KEY` are set
- Check key has proper permissions
- Verify RLS policies don't block service role

## License

MIT

## Contributing

Pull requests welcome. For major changes, open an issue first.
