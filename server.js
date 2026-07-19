const express = require('express');
const cors = require('cors');
const UAParser = require('ua-parser-js');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// In-memory data store for POC
const trackingData = [];

// Helper to clean IP and handle proxy scenarios
function getClientIp(req) {
    const xForwardedFor = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    let ip = xForwardedFor || req.socket.remoteAddress;
    // Normalize localhost IP for local testing
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
    }
    return ip;
}

// Handle the tracking link
app.get('/track', async (req, res) => {
    const userId = req.query.user_id || 'anonymous';
    const ip = getClientIp(req);

    // Parse User-Agent
    const uaString = req.headers['user-agent'] || '';
    const parser = new UAParser(uaString);
    const uaResult = parser.getResult();

    const deviceBrand = uaResult.device.vendor || 'Unknown';
    const osName = uaResult.os.name || 'Unknown';
    const deviceStr = `${deviceBrand} / ${osName}`;
    const browserStr = uaResult.browser.name || 'Unknown';

    // Get IP Geolocation using ipapi.co
    let city = 'Unknown', region = 'Unknown', country = 'Unknown', isp = 'Unknown';
    try {
        // Fetch detailed IP info (free tier limited, fallback handled)
        const geoResp = await fetch(`https://ipapi.co/${ip}/json/`);
        if (geoResp.ok) {
            const geoData = await geoResp.json();
            if (!geoData.error) {
                city = geoData.city || 'Unknown';
                region = geoData.region || 'Unknown';
                country = geoData.country_name || 'Unknown';
                isp = geoData.org || 'Unknown';
            }
        }
    } catch (e) {
        console.error('IP Geolocation error:', e.message);
    }

    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
    
    // Store in exact JSON structure requested
    const sessionData = {
        sessionId, // Kept for internal matching but omitted in output
        user_id: userId,
        ip: ip,
        city: city,
        region: region,
        country: country,
        isp: isp,
        device: deviceStr,
        browser: browserStr,
        screen: "Pending...",
        timezone: "Pending...",
        gps: "Pending..."
    };

    trackingData.push(sessionData);
    console.log(`[New Session Captured] User: ${userId}, Session: ${sessionId}`);

    // Read the tracking page template and inject sessionId so frontend can update it
    let htmlTemplate = fs.readFileSync(path.join(__dirname, 'public', 'track.html'), 'utf-8');
    htmlTemplate = htmlTemplate.replace('{{SESSION_ID}}', sessionId);
    htmlTemplate = htmlTemplate.replace('{{TARGET_URL}}', '/success.html');

    res.send(htmlTemplate);
});

// Endpoint to receive precise geolocation and enriched client data from frontend
app.post('/api/location', (req, res) => {
    const { sessionId, latitude, longitude, error, screen, timezone } = req.body;
    
    const session = trackingData.find(s => s.sessionId === sessionId);
    if (session) {
        if (screen) session.screen = screen;
        if (timezone) session.timezone = timezone;

        if (latitude && longitude) {
            session.gps = `${latitude}, ${longitude}`;
            console.log(`[Location Updated] Session: ${sessionId}, Method: GPS`);
        } else if (error) {
            session.gps = "denied or unavailable";
            console.log(`[Location Denied/Failed] Session: ${sessionId}, Error: ${error}`);
        }
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, message: 'Session not found' });
    }
});

// Admin endpoint to view structured data
app.get('/admin/data', (req, res) => {
    // Remove internal sessionId to match exactly the required JSON format
    const cleanData = trackingData.map(({ sessionId, ...rest }) => rest);
    res.json(cleanData);
});

app.listen(PORT, () => {
    console.log(`Tracking server running on http://localhost:${PORT}`);
    console.log(`Test link: http://localhost:${PORT}/track?user_id=EMP001`);
    console.log(`Admin Data link: http://localhost:${PORT}/admin/data`);
});
